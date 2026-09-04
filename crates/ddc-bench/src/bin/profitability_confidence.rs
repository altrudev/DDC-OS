use ddc_core::{
    evaluate_transition, propose_shared_delta, AuthoritySet, ComputeId, Dimension,
    DimensionalSnapshot, EffectClass, ExecutionDescriptor, FrequencyObservation, PolicyCaps,
    RadialEvidence, RadialFinding, RadialSignal, ResourceVector, SecurityContext,
    TransitionDisposition, TransitionProposal,
};
use std::collections::BTreeSet;
use std::hint::black_box;
use std::time::{Duration, Instant};

const CHANNEL_COUNTS: [usize; 7] = [1, 2, 4, 8, 16, 32, 64];
const OVERLAP_BASIS_POINTS: [u32; 15] = [
    0, 100, 200, 300, 400, 500, 600, 800, 1000, 1200, 1500, 2000, 4000, 8000, 10000,
];
const EPOCHS: usize = 9;
const PAIRS_PER_EPOCH: usize = 9;
const TOTAL_WORDS_PER_CHANNEL: usize = 262_144;

// Experimental confidence criteria only. They are benchmark policy candidates,
// not execution authority and not a canonical DDC rule.
const ENTER_MEDIAN_SPEEDUP: f64 = 1.05;
const ENTER_P25_SPEEDUP: f64 = 1.01;
const ENTER_PROFITABLE_EPOCHS: usize = 7;
const RETAIN_MEDIAN_SPEEDUP: f64 = 1.00;
const RETAIN_P25_SPEEDUP: f64 = 0.98;
const RETAIN_PROFITABLE_EPOCHS: usize = 5;

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

#[derive(Clone, Copy)]
struct PairSample {
    baseline_ns: u128,
    governed_ns: u128,
}

#[derive(Clone, Copy)]
struct EpochResult {
    median_speedup: f64,
    baseline_median_ns: u128,
    governed_median_ns: u128,
    profitable: bool,
}

fn id(label: &str, value: u64, epoch: usize) -> ComputeId {
    let value_bytes = value.to_le_bytes();
    let epoch_bytes = (epoch as u64).to_le_bytes();
    ComputeId::derive(
        "ddc-os-exp0005-profitability-confidence",
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
        .map(|delta| {
            sum_words(black_box(shared)) + sum_words(black_box(delta.as_slice()))
        })
        .collect()
}

fn raw_ddc(shared: &[u64], deltas: &[Vec<u64>]) -> Vec<u128> {
    let shared_sum = sum_words(black_box(shared));
    deltas
        .iter()
        .map(|delta| shared_sum + sum_words(black_box(delta.as_slice())))
        .collect()
}

fn build_transition(task_index: u64, total_words: usize, epoch: usize) -> TransitionProposal {
    let predecessor = id("predecessor", task_index, epoch);
    let successor_candidate = id("successor", task_index, epoch);
    let resources = ResourceVector {
        cpu_work_units: total_words as u64,
        memory_bytes: (total_words as u64).saturating_mul(8),
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
        0xDDC0_0005u64
            .wrapping_add(overlap_bp as u64)
            .wrapping_add(epoch_seed),
    );
    let deltas: Vec<Vec<u64>> = (0..channels)
        .map(|index| {
            sequence(
                unique_words,
                0xA11C_E500u64
                    .wrapping_add((overlap_bp as u64) << 16)
                    .wrapping_add(epoch_seed)
                    .wrapping_add(index as u64),
            )
        })
        .collect();

    let security = SecurityContext::from_trusted_observation(
        id("principal", 0, epoch),
        id("isolation", 0, epoch),
        AuthoritySet::new(["ddc:exp0005-os"]),
    );
    let task_authority = AuthoritySet::new(["ddc:exp0005-pure"]);
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

    let transitions: Vec<_> = (0..channels as u64)
        .map(|index| build_transition(index + 1, TOTAL_WORDS_PER_CHANNEL, epoch))
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
        .expect("EXP-0005 policy proposal must remain valid");

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

fn percentile_u128(values: &[u128], percentile: usize) -> u128 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = ((percentile * sorted.len()) + 99) / 100;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

fn percentile_f64(values: &[f64], percentile: usize) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let rank = ((percentile * sorted.len()) + 99) / 100;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

fn speedup(baseline_ns: u128, governed_ns: u128) -> f64 {
    baseline_ns as f64 / governed_ns.max(1) as f64
}

fn run_epoch(case: &Case, epoch: usize) -> EpochResult {
    let warm_baseline = baseline(&case.shared, &case.deltas);
    let warm_governed = governed_ddc(case);
    assert_eq!(warm_baseline, case.expected);
    assert_eq!(warm_governed, case.expected);

    let mut pairs = Vec::with_capacity(PAIRS_PER_EPOCH);
    for pair_index in 0..PAIRS_PER_EPOCH {
        let baseline_first = (pair_index + epoch) % 2 == 0;
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
        pairs.push(PairSample {
            baseline_ns,
            governed_ns,
        });
    }

    let baseline_values: Vec<_> = pairs.iter().map(|pair| pair.baseline_ns).collect();
    let governed_values: Vec<_> = pairs.iter().map(|pair| pair.governed_ns).collect();
    let pair_speedups: Vec<_> = pairs
        .iter()
        .map(|pair| speedup(pair.baseline_ns, pair.governed_ns))
        .collect();
    let median_speedup = percentile_f64(&pair_speedups, 50);

    EpochResult {
        median_speedup,
        baseline_median_ns: percentile_u128(&baseline_values, 50),
        governed_median_ns: percentile_u128(&governed_values, 50),
        profitable: median_speedup > 1.0,
    }
}

fn main() {
    println!("DDC-OS EXP-0005 profitability confidence / hysteresis candidate");
    println!("epochs={EPOCHS} pairs_per_epoch={PAIRS_PER_EPOCH}");
    println!("total_words_per_channel={TOTAL_WORDS_PER_CHANNEL}");
    println!("dimensions=8");
    println!("frequency_authoritative=false");
    println!("radial_authorizes_execution=false");
    println!("linux_observation_in_timed_region=false");
    println!("data_generation_in_timed_region=false");
    println!("enter_criteria=median>=1.05,p25>=1.01,profitable_epochs>=7/9");
    println!("retain_criteria=median>=1.00,p25>=0.98,profitable_epochs>=5/9");
    println!("criteria_are_experimental_not_authority=true");
    println!("channels,overlap_bp,overlap_pct,median_speedup,p25_speedup,p75_speedup,profitable_epochs,baseline_median_ns,governed_median_ns,enter_eligible,retain_eligible,verified");

    for channels in CHANNEL_COUNTS {
        let mut first_enter: Option<u32> = None;
        let mut first_retain: Option<u32> = None;

        for overlap_bp in OVERLAP_BASIS_POINTS {
            let mut epochs = Vec::with_capacity(EPOCHS);
            for epoch in 0..EPOCHS {
                let case = build_case(channels, overlap_bp, epoch);
                epochs.push(run_epoch(&case, epoch));
            }

            let speedups: Vec<_> = epochs.iter().map(|epoch| epoch.median_speedup).collect();
            let baseline_medians: Vec<_> = epochs
                .iter()
                .map(|epoch| epoch.baseline_median_ns)
                .collect();
            let governed_medians: Vec<_> = epochs
                .iter()
                .map(|epoch| epoch.governed_median_ns)
                .collect();
            let profitable_epochs = epochs.iter().filter(|epoch| epoch.profitable).count();
            let median_speedup = percentile_f64(&speedups, 50);
            let p25_speedup = percentile_f64(&speedups, 25);
            let p75_speedup = percentile_f64(&speedups, 75);
            let baseline_median_ns = percentile_u128(&baseline_medians, 50);
            let governed_median_ns = percentile_u128(&governed_medians, 50);

            let enter_eligible = channels >= 2
                && median_speedup >= ENTER_MEDIAN_SPEEDUP
                && p25_speedup >= ENTER_P25_SPEEDUP
                && profitable_epochs >= ENTER_PROFITABLE_EPOCHS;
            let retain_eligible = channels >= 2
                && median_speedup >= RETAIN_MEDIAN_SPEEDUP
                && p25_speedup >= RETAIN_P25_SPEEDUP
                && profitable_epochs >= RETAIN_PROFITABLE_EPOCHS;

            if enter_eligible && first_enter.is_none() {
                first_enter = Some(overlap_bp);
            }
            if retain_eligible && first_retain.is_none() {
                first_retain = Some(overlap_bp);
            }

            println!(
                "{channels},{overlap_bp},{:.2},{median_speedup:.4},{p25_speedup:.4},{p75_speedup:.4},{profitable_epochs},{baseline_median_ns},{governed_median_ns},{enter_eligible},{retain_eligible},true",
                overlap_bp as f64 / 100.0,
            );
        }

        match first_enter {
            Some(bp) => println!("enter_threshold,{channels},{bp},{:.2}", bp as f64 / 100.0),
            None => println!("enter_threshold,{channels},none,none"),
        }
        match first_retain {
            Some(bp) => println!("retain_threshold,{channels},{bp},{:.2}", bp as f64 / 100.0),
            None => println!("retain_threshold,{channels},none,none"),
        }
    }
}
