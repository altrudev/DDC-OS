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
const OVERLAP_BASIS_POINTS: [u32; 19] = [
    0, 1, 2, 5, 10, 25, 50, 100, 200, 500, 1000, 2000, 4000, 6000, 8000, 9000, 9500, 9900, 10000,
];
const SAMPLES: usize = 30;
const TOTAL_WORDS_PER_CHANNEL: usize = 262_144;

#[derive(Clone, Copy)]
enum Lane {
    Baseline,
    RawDdc,
    GovernedDdc,
}

#[derive(Clone, Copy)]
struct Sample {
    baseline_ns: u128,
    raw_ddc_ns: u128,
    governed_ddc_ns: u128,
}

struct Case {
    shared: Vec<u64>,
    deltas: Vec<Vec<u64>>,
    descriptors: Vec<ExecutionDescriptor>,
    transitions: Vec<TransitionProposal>,
    caps: PolicyCaps,
    expected: Vec<u128>,
}

fn id(label: &str, value: u64) -> ComputeId {
    let value_bytes = value.to_le_bytes();
    ComputeId::derive(
        "ddc-os-exp0004-profitability-overlap",
        &[label.as_bytes(), &value_bytes],
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

fn build_transition(task_index: u64, total_words: usize) -> TransitionProposal {
    let predecessor = id("predecessor", task_index);
    let successor_candidate = id("successor", task_index);
    let resources = ResourceVector {
        cpu_work_units: total_words as u64,
        memory_bytes: (total_words as u64).saturating_mul(8),
        io_bytes: 0,
        transport_bytes: 0,
    };
    let before = DimensionalSnapshot {
        semantic: id("semantic", task_index),
        authority: id("authority", task_index),
        state: id("state", task_index),
        resource: resources,
        security: id("security", task_index),
        physical: id("physical", 0),
        frequency: FrequencyObservation {
            sample_window_ns: 1_000_000,
            event_count: task_index + 1,
            recurrence_count: task_index,
        },
        lineage: id("lineage", 0),
    };
    let mut after = before;
    after.frequency.event_count = after.frequency.event_count.saturating_add(1);
    after.frequency.recurrence_count = after.frequency.recurrence_count.saturating_add(1);

    let mut radial = RadialEvidence::new(successor_candidate);
    radial.push(RadialFinding {
        lens: Dimension::Semantic,
        evidence: id("semantic-evidence", task_index),
        signal: RadialSignal::Supports,
    });
    radial.push(RadialFinding {
        lens: Dimension::Frequency,
        evidence: id("frequency-evidence", task_index),
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

fn build_case(channels: usize, overlap_bp: u32) -> Case {
    let shared_words = TOTAL_WORDS_PER_CHANNEL.saturating_mul(overlap_bp as usize) / 10_000;
    let unique_words = TOTAL_WORDS_PER_CHANNEL - shared_words;

    let shared = sequence(shared_words, 0xDDC0_0004u64.wrapping_add(overlap_bp as u64));
    let deltas: Vec<Vec<u64>> = (0..channels)
        .map(|index| {
            sequence(
                unique_words,
                0xA11C_E400u64
                    .wrapping_add((overlap_bp as u64) << 16)
                    .wrapping_add(index as u64),
            )
        })
        .collect();

    let security = SecurityContext::from_trusted_observation(
        id("principal", 0),
        id("isolation", 0),
        AuthoritySet::new(["ddc:exp0004-os"]),
    );
    let task_authority = AuthoritySet::new(["ddc:exp0004-pure"]);
    let executable = id("executable", 0);
    let shared_dependency_state = id("dependencies", 0);
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
                id("no-shared-state", task_id)
            } else {
                id("shared-state", overlap_bp as u64)
            };
            ExecutionDescriptor {
                task_id,
                executable,
                shared_state,
                shared_dependency_state,
                delta_state: id("delta-state", task_id),
                security: security.clone(),
                task_authority: task_authority.clone(),
                effects: EffectClass::Pure,
                expected_resources: per_task_resources,
            }
        })
        .collect();

    let transitions: Vec<_> = (0..channels as u64)
        .map(|index| build_transition(index + 1, TOTAL_WORDS_PER_CHANNEL))
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
        .expect("EXP-0004 policy proposal must remain valid");

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
        Lane::RawDdc => {
            let result = raw_ddc(&case.shared, &case.deltas);
            assert_eq!(black_box(&result), black_box(&case.expected));
            result
        }
        Lane::GovernedDdc => governed_ddc(case),
    };
    black_box(result);
    start.elapsed()
}

fn percentile_ns(values: &[u128], percentile: usize) -> u128 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = (percentile * sorted.len()).div_ceil(100);
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

fn order(sample: usize) -> [Lane; 3] {
    match sample % 6 {
        0 => [Lane::Baseline, Lane::RawDdc, Lane::GovernedDdc],
        1 => [Lane::Baseline, Lane::GovernedDdc, Lane::RawDdc],
        2 => [Lane::RawDdc, Lane::Baseline, Lane::GovernedDdc],
        3 => [Lane::RawDdc, Lane::GovernedDdc, Lane::Baseline],
        4 => [Lane::GovernedDdc, Lane::Baseline, Lane::RawDdc],
        _ => [Lane::GovernedDdc, Lane::RawDdc, Lane::Baseline],
    }
}

fn speedup(baseline_ns: u128, candidate_ns: u128) -> f64 {
    baseline_ns as f64 / candidate_ns.max(1) as f64
}

fn main() {
    println!("DDC-OS EXP-0004 governed profitability / overlap sweep");
    println!("samples={SAMPLES}");
    println!("total_words_per_channel={TOTAL_WORDS_PER_CHANNEL}");
    println!("dimensions=8");
    println!("frequency_authoritative=false");
    println!("radial_authorizes_execution=false");
    println!("timed_governed_lane=policy_planning+proposal_clone+transition_gate+shared_delta_or_baseline+exact_verification");
    println!("linux_observation_in_timed_region=false");
    println!("data_generation_in_timed_region=false");
    println!("channels,overlap_bp,overlap_pct,shared_words,unique_words,baseline_p50_ns,baseline_p95_ns,raw_ddc_p50_ns,raw_ddc_p95_ns,governed_p50_ns,governed_p95_ns,raw_speedup,governed_speedup,governed_profitable,verified");

    for channels in CHANNEL_COUNTS {
        let mut first_profitable: Option<u32> = None;

        for overlap_bp in OVERLAP_BASIS_POINTS {
            let case = build_case(channels, overlap_bp);
            let warm_baseline = baseline(&case.shared, &case.deltas);
            let warm_raw = raw_ddc(&case.shared, &case.deltas);
            let warm_governed = governed_ddc(&case);
            assert_eq!(warm_baseline, case.expected);
            assert_eq!(warm_raw, case.expected);
            assert_eq!(warm_governed, case.expected);

            let mut samples = Vec::with_capacity(SAMPLES);
            for sample_index in 0..SAMPLES {
                let mut baseline_ns = 0u128;
                let mut raw_ddc_ns = 0u128;
                let mut governed_ddc_ns = 0u128;
                for lane in order(sample_index) {
                    let elapsed = run_lane(&case, lane).as_nanos();
                    match lane {
                        Lane::Baseline => baseline_ns = elapsed,
                        Lane::RawDdc => raw_ddc_ns = elapsed,
                        Lane::GovernedDdc => governed_ddc_ns = elapsed,
                    }
                }
                samples.push(Sample {
                    baseline_ns,
                    raw_ddc_ns,
                    governed_ddc_ns,
                });
            }

            let baseline_values: Vec<_> = samples.iter().map(|sample| sample.baseline_ns).collect();
            let raw_values: Vec<_> = samples.iter().map(|sample| sample.raw_ddc_ns).collect();
            let governed_values: Vec<_> = samples
                .iter()
                .map(|sample| sample.governed_ddc_ns)
                .collect();
            let baseline_p50 = percentile_ns(&baseline_values, 50);
            let baseline_p95 = percentile_ns(&baseline_values, 95);
            let raw_p50 = percentile_ns(&raw_values, 50);
            let raw_p95 = percentile_ns(&raw_values, 95);
            let governed_p50 = percentile_ns(&governed_values, 50);
            let governed_p95 = percentile_ns(&governed_values, 95);
            let profitable = governed_p50 < baseline_p50;
            if profitable && first_profitable.is_none() {
                first_profitable = Some(overlap_bp);
            }

            let shared_words = case.shared.len();
            let unique_words = TOTAL_WORDS_PER_CHANNEL - shared_words;
            println!(
                "{channels},{overlap_bp},{:.2},{shared_words},{unique_words},{baseline_p50},{baseline_p95},{raw_p50},{raw_p95},{governed_p50},{governed_p95},{:.4},{:.4},{profitable},true",
                overlap_bp as f64 / 100.0,
                speedup(baseline_p50, raw_p50),
                speedup(baseline_p50, governed_p50),
            );
        }

        match first_profitable {
            Some(bp) => println!("threshold,{channels},{bp},{:.2}", bp as f64 / 100.0),
            None => println!("threshold,{channels},none,none"),
        }
    }
}
