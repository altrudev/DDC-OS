use ddc_core::{
    evaluate_profitability, evaluate_transition, propose_shared_delta, AuthoritySet, ComputeId,
    Dimension, DimensionalSnapshot, EffectClass, ExecutionDescriptor, FrequencyObservation,
    PolicyCaps, ProfitabilityAction, ProfitabilityEvidence, ProfitabilityPolicy, ProfitabilityState,
    RadialEvidence, RadialFinding, RadialSignal, ResourceVector, SecurityContext,
    TransitionDisposition, TransitionProposal,
};
use std::collections::BTreeSet;
use std::hint::black_box;
use std::time::{Duration, Instant};

const CHANNEL_COUNTS: [usize; 7] = [1, 2, 4, 8, 16, 32, 64];
const TRACE_OVERLAP_BP: [u32; 30] = [
    0, 500, 800, 1000, 800, 1000, 1200, 1000, 1200, 1500, 1200, 1000, 1500, 2000, 4000,
    2000, 1500, 1200, 1000, 800, 1000, 800, 600, 500, 600, 500, 400, 500, 400, 0,
];
const EPOCHS: usize = 9;
const PAIRS_PER_EPOCH: usize = 5;
const TOTAL_WORDS_PER_CHANNEL: usize = 262_144;

const EXPERIMENTAL_POLICY: ProfitabilityPolicy = ProfitabilityPolicy {
    enter_median_speedup_bp: 10_500,
    enter_lower_quartile_speedup_bp: 10_100,
    enter_profitable_epochs: 7,
    retain_median_speedup_bp: 10_000,
    retain_lower_quartile_speedup_bp: 9_800,
    retain_profitable_epochs: 5,
};

#[derive(Clone, Copy)]
enum Lane {
    Baseline,
    GovernedDdc,
}

struct Case {
    shared: Vec<u64>,
    deltas: Vec<Vec<u64>>,
    descriptors: Vec<ExecutionDescriptor>,
    transitions: Vec<TransitionProposal>,
    caps: PolicyCaps,
    expected: Vec<u128>,
}

fn id(label: &str, value: u64, epoch: usize) -> ComputeId {
    let value_bytes = value.to_le_bytes();
    let epoch_bytes = (epoch as u64).to_le_bytes();
    ComputeId::derive(
        "ddc-os-exp0006-adaptive-profitability",
        &[label.as_bytes(), &value_bytes, &epoch_bytes],
    )
}

fn sequence(len: usize, seed: u64) -> Vec<u64> {
    let mut state = seed.max(1);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push(state);
    }
    out
}

#[inline(never)]
fn sum_words(words: &[u64]) -> u128 {
    words
        .iter()
        .fold(0u128, |acc, &word| acc.wrapping_add(word as u128))
}

fn baseline(shared: &[u64], deltas: &[Vec<u64>]) -> Vec<u128> {
    deltas
        .iter()
        .map(|delta| sum_words(black_box(shared)) + sum_words(black_box(delta.as_slice())))
        .collect()
}

fn raw_ddc(shared: &[u64], deltas: &[Vec<u64>]) -> Vec<u128> {
    let shared_sum = sum_words(black_box(shared));
    deltas
        .iter()
        .map(|delta| shared_sum + sum_words(black_box(delta.as_slice())))
        .collect()
}

fn build_transition(task_index: u64, epoch: usize) -> TransitionProposal {
    let predecessor = id("predecessor", task_index, epoch);
    let successor_candidate = id("successor", task_index, epoch);
    let resources = ResourceVector {
        cpu_work_units: TOTAL_WORDS_PER_CHANNEL as u64,
        memory_bytes: (TOTAL_WORDS_PER_CHANNEL as u64).saturating_mul(8),
        io_bytes: 0,
        transport_bytes: 0,
    };
    let before = DimensionalSnapshot {
        semantic: id("semantic", task_index, epoch),
        authority: id("authority", task_index, epoch),
        state: id("state", task_index, epoch),
        resource: resources,
        security: id("security", task_index, epoch),
        physical: id("physical", 0, epoch),
        frequency: FrequencyObservation {
            sample_window_ns: 1_000_000,
            event_count: task_index + 1,
            recurrence_count: task_index,
        },
        lineage: id("lineage", 0, epoch),
    };
    let mut after = before;
    after.frequency.event_count = after.frequency.event_count.saturating_add(1);
    after.frequency.recurrence_count = after.frequency.recurrence_count.saturating_add(1);

    let mut radial = RadialEvidence::new(successor_candidate);
    radial.push(RadialFinding {
        lens: Dimension::Semantic,
        evidence: id("semantic-evidence", task_index, epoch),
        signal: RadialSignal::Supports,
    });
    radial.push(RadialFinding {
        lens: Dimension::Frequency,
        evidence: id("frequency-evidence", task_index, epoch),
        signal: RadialSignal::Supports,
    });

    TransitionProposal {
        predecessor,
        successor_candidate,
        before,
        after,
        permitted_changes: BTreeSet::from([Dimension::Frequency]),
        radial,
    }
}

fn build_case(channels: usize, overlap_bp: u32, epoch: usize) -> Case {
    let shared_words = TOTAL_WORDS_PER_CHANNEL.saturating_mul(overlap_bp as usize) / 10_000;
    let unique_words = TOTAL_WORDS_PER_CHANNEL - shared_words;
    let epoch_seed = (epoch as u64).wrapping_mul(0x9E37_79B9);

    let shared = sequence(
        shared_words,
        0xDDC0_0006u64
            .wrapping_add(overlap_bp as u64)
            .wrapping_add(epoch_seed),
    );
    let deltas: Vec<Vec<u64>> = (0..channels)
        .map(|index| {
            sequence(
                unique_words,
                0xA11C_E600u64
                    .wrapping_add((overlap_bp as u64) << 16)
                    .wrapping_add(epoch_seed)
                    .wrapping_add(index as u64),
            )
        })
        .collect();

    let security = SecurityContext::from_trusted_observation(
        id("principal", 0, epoch),
        id("isolation", 0, epoch),
        AuthoritySet::new(["ddc:exp0006-os"]),
    );
    let task_authority = AuthoritySet::new(["ddc:exp0006-pure"]);
    let executable = id("executable", 0, epoch);
    let shared_dependency_state = id("dependencies", 0, epoch);
    let per_task_resources = ResourceVector {
        cpu_work_units: TOTAL_WORDS_PER_CHANNEL as u64,
        memory_bytes: (TOTAL_WORDS_PER_CHANNEL as u64).saturating_mul(8),
        io_bytes: 0,
        transport_bytes: 0,
    };

    let descriptors: Vec<_> = (0..channels)
        .map(|index| {
            let task_id = index as u64 + 1;
            let shared_state = if shared_words == 0 {
                id("no-shared-state", task_id, epoch)
            } else {
                id("shared-state", overlap_bp as u64, epoch)
            };
            ExecutionDescriptor {
                task_id,
                executable,
                shared_state,
                shared_dependency_state,
                delta_state: id("delta-state", task_id, epoch),
                security: security.clone(),
                task_authority: task_authority.clone(),
                effects: EffectClass::Pure,
                expected_resources: per_task_resources,
            }
        })
        .collect();

    let transitions = (0..channels as u64)
        .map(|index| build_transition(index + 1, epoch))
        .collect();

    let caps = PolicyCaps {
        max_group_members: 64,
        group_resource_caps: ResourceVector {
            cpu_work_units: (TOTAL_WORDS_PER_CHANNEL as u64).saturating_mul(64),
            memory_bytes: (TOTAL_WORDS_PER_CHANNEL as u64)
                .saturating_mul(8)
                .saturating_mul(64),
            io_bytes: 0,
            transport_bytes: 0,
        },
    };

    let expected = baseline(&shared, &deltas);
    assert_eq!(expected, raw_ddc(&shared, &deltas));

    Case {
        shared,
        deltas,
        descriptors,
        transitions,
        caps,
        expected,
    }
}

fn governed_ddc(case: &Case) -> Vec<u128> {
    let policy = propose_shared_delta(black_box(&case.descriptors), case.caps)
        .expect("EXP-0006 policy proposal must remain valid");
    let all_grouped = policy.baseline_tasks.is_empty()
        && policy.shared_delta_candidates.len() == 1
        && policy.shared_delta_candidates[0].task_ids.len() == case.descriptors.len();

    if all_grouped {
        for task_id in &policy.shared_delta_candidates[0].task_ids {
            let index = (*task_id as usize).saturating_sub(1);
            let proposal = black_box(case.transitions[index].clone());
            let decision = black_box(evaluate_transition(proposal.predecessor, &proposal));
            if decision.disposition != TransitionDisposition::ShadowEligible
                || !decision.closure.is_closed()
                || proposal.radial.authorizes_execution()
                || proposal.before.frequency.is_authoritative()
            {
                return baseline(&case.shared, &case.deltas);
            }
        }
        let result = raw_ddc(&case.shared, &case.deltas);
        assert_eq!(black_box(&result), black_box(&case.expected));
        result
    } else {
        let result = baseline(&case.shared, &case.deltas);
        assert_eq!(black_box(&result), black_box(&case.expected));
        result
    }
}

fn run_lane(case: &Case, lane: Lane) -> Duration {
    let start = Instant::now();
    let result = match lane {
        Lane::Baseline => baseline(&case.shared, &case.deltas),
        Lane::GovernedDdc => governed_ddc(case),
    };
    black_box(result);
    start.elapsed()
}

fn percentile_u32(values: &[u32], percentile: usize) -> u32 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = (percentile * sorted.len()).div_ceil(100);
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

fn ratio_bp(baseline_ns: u128, governed_ns: u128) -> u32 {
    let scaled = baseline_ns.saturating_mul(10_000) / governed_ns.max(1);
    scaled.min(u32::MAX as u128) as u32
}

fn epoch_speedup_bp(case: &Case, epoch: usize) -> u32 {
    let warm_baseline = baseline(&case.shared, &case.deltas);
    let warm_governed = governed_ddc(case);
    assert_eq!(warm_baseline, case.expected);
    assert_eq!(warm_governed, case.expected);

    let mut ratios = Vec::with_capacity(PAIRS_PER_EPOCH);
    for pair_index in 0..PAIRS_PER_EPOCH {
        let baseline_first = (pair_index + epoch).is_multiple_of(2);
        let (baseline_ns, governed_ns) = if baseline_first {
            (
                run_lane(case, Lane::Baseline).as_nanos(),
                run_lane(case, Lane::GovernedDdc).as_nanos(),
            )
        } else {
            let governed_ns = run_lane(case, Lane::GovernedDdc).as_nanos();
            let baseline_ns = run_lane(case, Lane::Baseline).as_nanos();
            (baseline_ns, governed_ns)
        };
        ratios.push(ratio_bp(baseline_ns, governed_ns));
    }
    percentile_u32(&ratios, 50)
}

fn measure_evidence(channels: usize, overlap_bp: u32) -> ProfitabilityEvidence {
    let mut epoch_ratios = Vec::with_capacity(EPOCHS);
    for epoch in 0..EPOCHS {
        let case = build_case(channels, overlap_bp, epoch);
        epoch_ratios.push(epoch_speedup_bp(&case, epoch));
    }
    let profitable_epochs = epoch_ratios.iter().filter(|&&ratio| ratio > 10_000).count();
    ProfitabilityEvidence {
        candidate_count: channels,
        median_speedup_bp: percentile_u32(&epoch_ratios, 50),
        lower_quartile_speedup_bp: percentile_u32(&epoch_ratios, 25),
        profitable_epochs,
        total_epochs: EPOCHS,
    }
}

fn state_name(state: ProfitabilityState) -> &'static str {
    match state {
        ProfitabilityState::Baseline => "baseline",
        ProfitabilityState::ShadowCandidate => "shadow-candidate",
    }
}

fn action_name(action: ProfitabilityAction) -> &'static str {
    match action {
        ProfitabilityAction::StayBaseline => "stay-baseline",
        ProfitabilityAction::EnterShadowCandidate => "enter-shadow",
        ProfitabilityAction::RetainShadowCandidate => "retain-shadow",
        ProfitabilityAction::ExitToBaseline => "exit-baseline",
    }
}

fn main() {
    println!("DDC-OS EXP-0006 adaptive profitability gate");
    println!("epochs={EPOCHS} pairs_per_epoch={PAIRS_PER_EPOCH}");
    println!("total_words_per_channel={TOTAL_WORDS_PER_CHANNEL}");
    println!("policy_is_experimental_not_authority=true");
    println!("profitability_authorizes_execution=false");
    println!("enter=median>=10500bp,p25>=10100bp,profitable_epochs>=7/9");
    println!("retain=median>=10000bp,p25>=9800bp,profitable_epochs>=5/9");
    println!("trace_step,channels,overlap_pct,median_bp,p25_bp,profitable_epochs,previous,action,next,naive_state");

    for channels in CHANNEL_COUNTS {
        let mut adaptive_state = ProfitabilityState::Baseline;
        let mut naive_state = ProfitabilityState::Baseline;
        let mut adaptive_transitions = 0usize;
        let mut naive_transitions = 0usize;

        for (step, overlap_bp) in TRACE_OVERLAP_BP.into_iter().enumerate() {
            let evidence = measure_evidence(channels, overlap_bp);
            assert!(!evidence.authorizes_execution());
            let decision = evaluate_profitability(adaptive_state, evidence, EXPERIMENTAL_POLICY)
                .expect("EXP-0006 evidence and policy must remain valid");
            assert!(!decision.authorizes_execution());

            if decision.next != adaptive_state {
                adaptive_transitions += 1;
            }
            adaptive_state = decision.next;

            let naive_next = if channels >= 2 && evidence.median_speedup_bp > 10_000 {
                ProfitabilityState::ShadowCandidate
            } else {
                ProfitabilityState::Baseline
            };
            if naive_next != naive_state {
                naive_transitions += 1;
            }
            naive_state = naive_next;

            println!(
                "{step},{channels},{:.2},{},{},{},{},{},{},{}",
                overlap_bp as f64 / 100.0,
                evidence.median_speedup_bp,
                evidence.lower_quartile_speedup_bp,
                evidence.profitable_epochs,
                state_name(decision.previous),
                action_name(decision.action),
                state_name(decision.next),
                state_name(naive_state),
            );
        }

        println!(
            "summary,{channels},adaptive_transitions={adaptive_transitions},naive_transitions={naive_transitions},final_adaptive={},final_naive={}",
            state_name(adaptive_state),
            state_name(naive_state),
        );
    }
}
