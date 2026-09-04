use ddc_core::{
    evaluate_transition, propose_shared_delta, AuthoritySet, ComputeId, Dimension,
    DimensionalSnapshot, EffectClass, ExecutionDescriptor, FrequencyObservation, PolicyCaps,
    RadialEvidence, RadialFinding, RadialSignal, ResourceVector, TransitionDisposition,
    TransitionProposal,
};
use ddc_linux::observe_self_security;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs::read_to_string;
use std::io;

fn id(label: &str) -> ComputeId {
    ComputeId::derive("ddc-linux-probe-v0.3", &[label.as_bytes()])
}

fn observe_physical_boundary() -> io::Result<ComputeId> {
    let kernel = read_to_string("/proc/sys/kernel/osrelease")?;
    let online_cpus = read_to_string("/sys/devices/system/cpu/online")?;
    Ok(ComputeId::derive(
        "ddc-linux-physical-v0.3",
        &[
            std::env::consts::ARCH.as_bytes(),
            kernel.trim().as_bytes(),
            online_cpus.trim().as_bytes(),
        ],
    ))
}

fn main() -> Result<(), Box<dyn Error>> {
    let snapshot = observe_self_security()?;
    let security = snapshot.security_context();

    // Synthetic known-pure tasks exercise the OS policy boundary without
    // classifying arbitrary legacy processes as pure.
    let task_authority = AuthoritySet::new(["ddc:synthetic-pure-probe"]);
    let tasks: Vec<_> = (1..=64u64)
        .map(|task_id| ExecutionDescriptor {
            task_id,
            executable: id("synthetic-pure-executable"),
            shared_state: id("synthetic-shared-state"),
            shared_dependency_state: id("synthetic-shared-dependencies"),
            delta_state: ComputeId::derive("ddc-linux-probe-delta-v0.3", &[&task_id.to_le_bytes()]),
            security: security.clone(),
            task_authority: task_authority.clone(),
            effects: EffectClass::Pure,
            expected_resources: ResourceVector {
                cpu_work_units: 1,
                memory_bytes: 1,
                io_bytes: 0,
                transport_bytes: 0,
            },
        })
        .collect();

    let proposal = propose_shared_delta(
        &tasks,
        PolicyCaps {
            max_group_members: 64,
            group_resource_caps: ResourceVector {
                cpu_work_units: 64,
                memory_bytes: 64,
                io_bytes: 0,
                transport_bytes: 0,
            },
        },
    )
    .map_err(|err| io::Error::other(format!("policy proposal failed: {err:?}")))?;

    let largest_group = proposal
        .shared_delta_candidates
        .iter()
        .map(|candidate| candidate.task_ids.len())
        .max()
        .unwrap_or(0);

    let predecessor = id("probe-predecessor");
    let successor = id("probe-successor-candidate");
    let physical = observe_physical_boundary()?;
    let base_dimensions = DimensionalSnapshot {
        semantic: id("probe-semantic"),
        authority: task_authority.identity(),
        state: id("probe-state"),
        resource: ResourceVector {
            cpu_work_units: 64,
            memory_bytes: 64,
            io_bytes: 0,
            transport_bytes: 0,
        },
        security: security.identity(),
        physical,
        frequency: FrequencyObservation::default(),
        lineage: id("probe-lineage-v0.3"),
    };
    let mut observed_dimensions = base_dimensions;
    observed_dimensions.frequency = FrequencyObservation {
        sample_window_ns: 0,
        event_count: largest_group as u64,
        recurrence_count: largest_group.saturating_sub(1) as u64,
    };

    let mut radial = RadialEvidence::new(successor);
    radial.push(RadialFinding {
        lens: Dimension::Semantic,
        evidence: id("probe-semantic-evidence"),
        signal: RadialSignal::Supports,
    });
    radial.push(RadialFinding {
        lens: Dimension::Frequency,
        evidence: ComputeId::derive(
            "probe-frequency-evidence-v0.3",
            &[
                &observed_dimensions.frequency.event_count.to_le_bytes(),
                &observed_dimensions.frequency.recurrence_count.to_le_bytes(),
            ],
        ),
        signal: RadialSignal::Supports,
    });

    let transition = evaluate_transition(
        predecessor,
        &TransitionProposal {
            predecessor,
            successor_candidate: successor,
            before: base_dimensions,
            after: observed_dimensions,
            permitted_changes: BTreeSet::from([Dimension::Frequency]),
            radial,
        },
    );

    println!("DDC-OS v0.3 Linux observation probe");
    println!("security_observation=complete");
    println!("namespace_count={}", snapshot.namespace_count());
    println!(
        "candidate_groups={}",
        proposal.shared_delta_candidates.len()
    );
    println!("largest_group={largest_group}");
    println!("baseline_tasks={}", proposal.baseline_tasks.len());
    println!("dimensions=8");
    println!("frequency_authoritative=false");
    println!("radial_disposition=consistent");
    println!("transition=shadow-eligible");
    println!("kernel_writes=0");

    if largest_group != 64 || !proposal.baseline_tasks.is_empty() {
        return Err(io::Error::other("64-channel observation-only policy probe failed").into());
    }
    if transition.disposition != TransitionDisposition::ShadowEligible {
        return Err(io::Error::other("v0.3 Radial/dimensional shadow gate failed").into());
    }

    Ok(())
}
