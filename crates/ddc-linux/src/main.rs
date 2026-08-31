use ddc_core::{
    propose_shared_delta, ComputeId, EffectClass, ExecutionDescriptor, PolicyCaps, ResourceVector,
};
use ddc_linux::observe_self_security;
use std::error::Error;
use std::fmt::Write as _;

fn id(label: &str) -> ComputeId {
    ComputeId::derive("ddc-linux-probe-v0.2", &[label.as_bytes()])
}

fn hex(id: ComputeId) -> String {
    let mut out = String::with_capacity(64);
    for byte in id.as_bytes() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn main() -> Result<(), Box<dyn Error>> {
    let snapshot = observe_self_security()?;
    let security = snapshot.security_context();

    // Synthetic known-pure tasks exercise the OS policy boundary without
    // classifying arbitrary legacy processes as pure.
    let tasks: Vec<_> = (1..=64u64)
        .map(|task_id| ExecutionDescriptor {
            task_id,
            executable: id("synthetic-pure-executable"),
            shared_state: id("synthetic-shared-state"),
            shared_dependency_state: id("synthetic-shared-dependencies"),
            delta_state: ComputeId::derive(
                "ddc-linux-probe-delta-v0.2",
                &[&task_id.to_le_bytes()],
            ),
            security: security.clone(),
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
    )?;

    let largest_group = proposal
        .shared_delta_candidates
        .iter()
        .map(|candidate| candidate.task_ids.len())
        .max()
        .unwrap_or(0);

    println!("DDC-OS v0.2 Linux observation probe");
    println!("security_context={}", hex(security.identity()));
    println!("effective_uid={}", snapshot.effective_uid);
    println!("effective_gid={}", snapshot.effective_gid);
    println!("namespace_count={}", snapshot.namespaces.len());
    println!("candidate_groups={}", proposal.shared_delta_candidates.len());
    println!("largest_group={largest_group}");
    println!("baseline_tasks={}", proposal.baseline_tasks.len());
    println!("kernel_writes=0");

    if largest_group != 64 || !proposal.baseline_tasks.is_empty() {
        return Err("64-channel observation-only policy probe failed".into());
    }

    Ok(())
}
