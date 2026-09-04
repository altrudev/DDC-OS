use ddc_core::{
    evaluate_transition, ComputeId, Dimension, DimensionalSnapshot, FrequencyObservation,
    RadialEvidence, RadialFinding, RadialSignal, ResourceVector, TransitionDisposition,
    TransitionProposal,
};
use std::collections::BTreeSet;
use std::hint::black_box;
use std::time::{Duration, Instant};

const CHANNEL_COUNTS: [usize; 7] = [1, 2, 4, 8, 16, 32, 64];
const SAMPLES: usize = 30;
const TARGET_EVALUATIONS_PER_SAMPLE: usize = 10_000;
const WARMUP_EVALUATIONS: usize = 2_000;

fn id(label: &str, index: u64) -> ComputeId {
    let index_bytes = index.to_le_bytes();
    ComputeId::derive(
        "ddc-os-exp0003-governed-overhead",
        &[label.as_bytes(), &index_bytes],
    )
}

fn build_proposal(index: u64) -> TransitionProposal {
    let predecessor = id("predecessor", index);
    let successor_candidate = id("successor", index);

    let before = DimensionalSnapshot {
        semantic: id("semantic", index),
        authority: id("authority", index),
        state: id("state", index),
        resource: ResourceVector {
            cpu_work_units: 1,
            memory_bytes: 64,
            io_bytes: 0,
            transport_bytes: 0,
        },
        security: id("security", index),
        physical: id("physical", index),
        frequency: FrequencyObservation {
            sample_window_ns: 1_000_000,
            event_count: index + 1,
            recurrence_count: index,
        },
        lineage: id("lineage", index),
    };

    let mut after = before;
    after.frequency.event_count = after.frequency.event_count.saturating_add(1);
    after.frequency.recurrence_count = after.frequency.recurrence_count.saturating_add(1);

    let mut radial = RadialEvidence::new(successor_candidate);
    radial.push(RadialFinding {
        lens: Dimension::Semantic,
        evidence: id("semantic-evidence", index),
        signal: RadialSignal::Supports,
    });
    radial.push(RadialFinding {
        lens: Dimension::Frequency,
        evidence: id("frequency-evidence", index),
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

fn validate_proposals(proposals: &[TransitionProposal]) {
    for proposal in proposals {
        assert!(!proposal.before.frequency.is_authoritative());
        assert!(!proposal.radial.authorizes_execution());
        let decision = evaluate_transition(proposal.predecessor, proposal);
        assert_eq!(decision.disposition, TransitionDisposition::ShadowEligible);
        assert!(decision.closure.is_closed());
        assert_eq!(decision.closure.changed, BTreeSet::from([Dimension::Frequency]));
    }
}

fn consume_decision(proposal: &TransitionProposal) -> u64 {
    let decision = black_box(evaluate_transition(proposal.predecessor, proposal));
    let disposition = match decision.disposition {
        TransitionDisposition::Baseline => 1u64,
        TransitionDisposition::ShadowEligible => 2u64,
    };
    disposition
        .wrapping_add(decision.closure.changed.len() as u64)
        .wrapping_add((decision.closure.violations.len() as u64) << 8)
}

fn time_gate_only(proposals: &[TransitionProposal], rounds: usize) -> Duration {
    let start = Instant::now();
    let mut checksum = 0u64;
    for round in 0..rounds {
        for proposal in black_box(proposals) {
            checksum = checksum
                .wrapping_add(consume_decision(proposal))
                .rotate_left(((round as u32) & 31) + 1);
        }
    }
    black_box(checksum);
    start.elapsed()
}

fn time_materialize_and_gate(proposals: &[TransitionProposal], rounds: usize) -> Duration {
    let start = Instant::now();
    let mut checksum = 0u64;
    for round in 0..rounds {
        for proposal in black_box(proposals) {
            // Clone the complete public proposal to include in-process materialization
            // costs for snapshots, permitted-dimension state and Radial evidence.
            // Linux/procfs observation and identity derivation remain outside this
            // timed region and are reported explicitly below.
            let materialized = black_box(proposal.clone());
            checksum = checksum
                .wrapping_add(consume_decision(&materialized))
                .rotate_left(((round as u32) & 31) + 1);
        }
    }
    black_box(checksum);
    start.elapsed()
}

fn nearest_rank(values: &mut [u128], percentile: usize) -> u128 {
    values.sort_unstable();
    let rank = ((percentile * values.len()) + 99) / 100;
    values[rank.saturating_sub(1).min(values.len() - 1)]
}

fn per_candidate_ns(elapsed: Duration, evaluations: usize) -> u128 {
    elapsed.as_nanos() / evaluations.max(1) as u128
}

fn main() {
    println!("DDC-OS EXP-0003 governed-overhead benchmark");
    println!("samples={SAMPLES} target_evaluations_per_sample={TARGET_EVALUATIONS_PER_SAMPLE}");
    println!("dimensions=8");
    println!("frequency_authoritative=false");
    println!("radial_authorizes_execution=false");
    println!("linux_observation_in_timed_region=false");
    println!("identity_derivation_in_timed_region=false");
    println!("materialized_lane=proposal_clone_plus_transition_evaluation");
    println!("gate_lane=transition_evaluation_only");
    println!("channels,rounds,gate_p50_ns_per_candidate,gate_p95_ns_per_candidate,materialized_p50_ns_per_candidate,materialized_p95_ns_per_candidate,shadow_eligible");

    for channels in CHANNEL_COUNTS {
        let proposals: Vec<_> = (0..channels as u64).map(build_proposal).collect();
        validate_proposals(&proposals);

        let warmup_rounds = (WARMUP_EVALUATIONS / channels).max(1);
        black_box(time_gate_only(&proposals, warmup_rounds));
        black_box(time_materialize_and_gate(&proposals, warmup_rounds));

        let rounds = (TARGET_EVALUATIONS_PER_SAMPLE / channels).max(1);
        let evaluations = rounds * channels;
        let mut gate_samples = Vec::with_capacity(SAMPLES);
        let mut materialized_samples = Vec::with_capacity(SAMPLES);

        for sample in 0..SAMPLES {
            // Alternate lane order to reduce systematic thermal/frequency bias.
            let (gate, materialized) = if sample % 2 == 0 {
                (
                    time_gate_only(&proposals, rounds),
                    time_materialize_and_gate(&proposals, rounds),
                )
            } else {
                let materialized = time_materialize_and_gate(&proposals, rounds);
                let gate = time_gate_only(&proposals, rounds);
                (gate, materialized)
            };
            gate_samples.push(per_candidate_ns(gate, evaluations));
            materialized_samples.push(per_candidate_ns(materialized, evaluations));
        }

        let gate_p50 = nearest_rank(&mut gate_samples.clone(), 50);
        let gate_p95 = nearest_rank(&mut gate_samples, 95);
        let materialized_p50 = nearest_rank(&mut materialized_samples.clone(), 50);
        let materialized_p95 = nearest_rank(&mut materialized_samples, 95);

        println!(
            "{channels},{rounds},{gate_p50},{gate_p95},{materialized_p50},{materialized_p95},true"
        );
    }
}
