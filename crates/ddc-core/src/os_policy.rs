use crate::{AuthoritySet, ComputeId, ResourceVector};
use std::collections::{BTreeMap, BTreeSet};

/// v0.2 deliberately treats only pure computation as shareable.
///
/// Unknown, read-only, or externally effecting work remains on the baseline
/// path until a later DDC gate proves a narrower safe model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectClass {
    Pure,
    ReadOnlyExternal,
    ExternalEffect,
}

/// Security facts that a trusted OS adapter derives from kernel-observed state.
///
/// `principal` identifies the effective subject. `isolation_context` is a
/// digest over the complete OS isolation facts selected by the adapter. The
/// authority stored here describes the observed OS-level authority boundary;
/// logical DDC/capsule authority is bound separately per execution descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityContext {
    principal: ComputeId,
    isolation_context: ComputeId,
    authority: AuthoritySet,
}

impl SecurityContext {
    /// Construct from facts observed by a trusted OS adapter.
    ///
    /// This type is not itself an authentication mechanism. Production code
    /// must prevent applications from supplying these values directly.
    pub fn from_trusted_observation(
        principal: ComputeId,
        isolation_context: ComputeId,
        authority: AuthoritySet,
    ) -> Self {
        Self {
            principal,
            isolation_context,
            authority,
        }
    }

    pub fn identity(&self) -> ComputeId {
        let authority = self.authority.identity();
        ComputeId::derive(
            "os-security-context-v0.2",
            &[
                self.principal.as_bytes(),
                self.isolation_context.as_bytes(),
                authority.as_bytes(),
            ],
        )
    }
}

/// One OS-visible compute request before scheduler placement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionDescriptor {
    pub task_id: u64,
    pub executable: ComputeId,
    pub shared_state: ComputeId,
    pub shared_dependency_state: ComputeId,
    pub delta_state: ComputeId,
    pub security: SecurityContext,
    /// Exact logical DDC/capsule authority for this task. This remains separate
    /// from process-level Linux authority because multiple logical tasks in one
    /// process may intentionally have different permissions.
    pub task_authority: AuthoritySet,
    pub effects: EffectClass,
    /// A bounded planning estimate only. Actual execution must still be
    /// contained by kernel-enforced resource ceilings before promotion.
    pub expected_resources: ResourceVector,
}

impl ExecutionDescriptor {
    /// Family identity for a potentially shareable pure computation.
    ///
    /// Delta state is intentionally excluded: members may diverge in their
    /// per-channel delta. Exact executable, shared state, shared dependencies,
    /// OS security context and logical task authority must all match.
    pub fn share_family(&self) -> Option<ComputeId> {
        if self.effects != EffectClass::Pure {
            return None;
        }
        let security = self.security.identity();
        let task_authority = self.task_authority.identity();
        Some(ComputeId::derive(
            "os-share-family-v0.2",
            &[
                self.executable.as_bytes(),
                self.shared_state.as_bytes(),
                self.shared_dependency_state.as_bytes(),
                security.as_bytes(),
                task_authority.as_bytes(),
            ],
        ))
    }
}

/// Hard v0.2 upper bound. Increasing this is a versioned safety transition.
pub const ABSOLUTE_MAX_GROUP_MEMBERS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyCaps {
    pub max_group_members: usize,
    pub group_resource_caps: ResourceVector,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyRejectReason {
    InvalidGroupLimit,
    DuplicateTaskId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaselineReason {
    NonPure,
    NoCompatiblePeer,
    ResourceCapExceeded,
}

/// A candidate family is only a proposal for later shadow execution and DDC
/// admission. It is not permission to change scheduler or memory policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedDeltaCandidate {
    pub family: ComputeId,
    pub task_ids: Vec<u64>,
    pub estimated_resources: ResourceVector,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaselineTask {
    pub task_id: u64,
    pub reason: BaselineReason,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyProposal {
    pub shared_delta_candidates: Vec<SharedDeltaCandidate>,
    pub baseline_tasks: Vec<BaselineTask>,
}

/// Detect safe-to-test sharing candidates without authorizing execution.
///
/// This function is intentionally conservative:
/// - only pure work can enter a candidate;
/// - OS security context and logical task authority are in the family identity;
/// - duplicate task ids fail the whole proposal;
/// - groups never exceed 64 members in v0.2;
/// - resource-estimate overflow or cap pressure returns work to baseline.
pub fn propose_shared_delta(
    tasks: &[ExecutionDescriptor],
    caps: PolicyCaps,
) -> Result<PolicyProposal, PolicyRejectReason> {
    if !(2..=ABSOLUTE_MAX_GROUP_MEMBERS).contains(&caps.max_group_members) {
        return Err(PolicyRejectReason::InvalidGroupLimit);
    }

    let mut seen = BTreeSet::new();
    for task in tasks {
        if !seen.insert(task.task_id) {
            return Err(PolicyRejectReason::DuplicateTaskId);
        }
    }

    let mut proposal = PolicyProposal::default();
    let mut families: BTreeMap<ComputeId, Vec<&ExecutionDescriptor>> = BTreeMap::new();

    for task in tasks {
        match task.share_family() {
            Some(family) => families.entry(family).or_default().push(task),
            None => proposal.baseline_tasks.push(BaselineTask {
                task_id: task.task_id,
                reason: BaselineReason::NonPure,
            }),
        }
    }

    for (family, members) in families {
        let mut chunk: Vec<&ExecutionDescriptor> = Vec::new();
        let mut resources = ResourceVector::default();

        let flush = |chunk: &mut Vec<&ExecutionDescriptor>,
                     resources: &mut ResourceVector,
                     proposal: &mut PolicyProposal| {
            if chunk.len() >= 2 {
                proposal.shared_delta_candidates.push(SharedDeltaCandidate {
                    family,
                    task_ids: chunk.iter().map(|task| task.task_id).collect(),
                    estimated_resources: *resources,
                });
            } else if let Some(task) = chunk.first() {
                proposal.baseline_tasks.push(BaselineTask {
                    task_id: task.task_id,
                    reason: BaselineReason::NoCompatiblePeer,
                });
            }
            chunk.clear();
            *resources = ResourceVector::default();
        };

        for task in members {
            let next = resources.checked_add(task.expected_resources);
            let would_exceed_resources = next
                .map(|value| !value.within(caps.group_resource_caps))
                .unwrap_or(true);
            let would_exceed_members = chunk.len() == caps.max_group_members;

            if would_exceed_members || would_exceed_resources {
                flush(&mut chunk, &mut resources, &mut proposal);
            }

            match resources.checked_add(task.expected_resources) {
                Some(next) if next.within(caps.group_resource_caps) => {
                    resources = next;
                    chunk.push(task);
                }
                _ => proposal.baseline_tasks.push(BaselineTask {
                    task_id: task.task_id,
                    reason: BaselineReason::ResourceCapExceeded,
                }),
            }
        }

        flush(&mut chunk, &mut resources, &mut proposal);
    }

    proposal
        .shared_delta_candidates
        .sort_by_key(|candidate| candidate.task_ids.first().copied().unwrap_or(u64::MAX));
    proposal.baseline_tasks.sort_by_key(|task| task.task_id);
    Ok(proposal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(label: &str) -> ComputeId {
        ComputeId::derive("os-policy-test", &[label.as_bytes()])
    }

    fn security(principal: &str, isolation: &str, authority: &[&str]) -> SecurityContext {
        SecurityContext::from_trusted_observation(
            id(principal),
            id(isolation),
            AuthoritySet::new(authority.iter().copied()),
        )
    }

    fn task(task_id: u64, delta: &str) -> ExecutionDescriptor {
        ExecutionDescriptor {
            task_id,
            executable: id("exe"),
            shared_state: id("shared"),
            shared_dependency_state: id("shared-deps"),
            delta_state: id(delta),
            security: security("principal-a", "isolation-a", &["linux:cap-a"]),
            task_authority: AuthoritySet::new(["ddc:compute"]),
            effects: EffectClass::Pure,
            expected_resources: ResourceVector {
                cpu_work_units: 1,
                memory_bytes: 1,
                io_bytes: 0,
                transport_bytes: 0,
            },
        }
    }

    fn caps(max_group_members: usize) -> PolicyCaps {
        PolicyCaps {
            max_group_members,
            group_resource_caps: ResourceVector {
                cpu_work_units: 1_000,
                memory_bytes: 1_000,
                io_bytes: 1_000,
                transport_bytes: 1_000,
            },
        }
    }

    #[test]
    fn groups_different_deltas_when_shared_state_and_security_match() {
        let proposal = propose_shared_delta(&[task(1, "d1"), task(2, "d2")], caps(64)).unwrap();
        assert_eq!(proposal.shared_delta_candidates.len(), 1);
        assert_eq!(proposal.shared_delta_candidates[0].task_ids, vec![1, 2]);
        assert!(proposal.baseline_tasks.is_empty());
    }

    #[test]
    fn refuses_cross_principal_sharing() {
        let a = task(1, "d1");
        let mut b = task(2, "d2");
        b.security = security("principal-b", "isolation-a", &["linux:cap-a"]);
        let proposal = propose_shared_delta(&[a, b], caps(64)).unwrap();
        assert!(proposal.shared_delta_candidates.is_empty());
        assert_eq!(proposal.baseline_tasks.len(), 2);
    }

    #[test]
    fn refuses_cross_isolation_sharing() {
        let a = task(1, "d1");
        let mut b = task(2, "d2");
        b.security = security("principal-a", "isolation-b", &["linux:cap-a"]);
        let proposal = propose_shared_delta(&[a, b], caps(64)).unwrap();
        assert!(proposal.shared_delta_candidates.is_empty());
        assert_eq!(proposal.baseline_tasks.len(), 2);
    }

    #[test]
    fn refuses_os_authority_mismatch() {
        let a = task(1, "d1");
        let mut b = task(2, "d2");
        b.security = security(
            "principal-a",
            "isolation-a",
            &["linux:cap-a", "linux:cap-b"],
        );
        let proposal = propose_shared_delta(&[a, b], caps(64)).unwrap();
        assert!(proposal.shared_delta_candidates.is_empty());
        assert_eq!(proposal.baseline_tasks.len(), 2);
    }

    #[test]
    fn refuses_logical_task_authority_mismatch_inside_same_process() {
        let a = task(1, "d1");
        let mut b = task(2, "d2");
        b.task_authority = AuthoritySet::new(["ddc:compute", "ddc:network"]);
        let proposal = propose_shared_delta(&[a, b], caps(64)).unwrap();
        assert!(proposal.shared_delta_candidates.is_empty());
        assert_eq!(proposal.baseline_tasks.len(), 2);
    }

    #[test]
    fn side_effecting_work_is_baseline_only() {
        let mut a = task(1, "d1");
        let mut b = task(2, "d2");
        a.effects = EffectClass::ExternalEffect;
        b.effects = EffectClass::ExternalEffect;
        let proposal = propose_shared_delta(&[a, b], caps(64)).unwrap();
        assert!(proposal.shared_delta_candidates.is_empty());
        assert!(proposal
            .baseline_tasks
            .iter()
            .all(|task| task.reason == BaselineReason::NonPure));
    }

    #[test]
    fn read_only_external_work_is_baseline_only_in_v02() {
        let mut a = task(1, "d1");
        let mut b = task(2, "d2");
        a.effects = EffectClass::ReadOnlyExternal;
        b.effects = EffectClass::ReadOnlyExternal;
        let proposal = propose_shared_delta(&[a, b], caps(64)).unwrap();
        assert!(proposal.shared_delta_candidates.is_empty());
        assert_eq!(proposal.baseline_tasks.len(), 2);
    }

    #[test]
    fn supports_exactly_sixty_four_members_but_not_a_larger_single_group() {
        let tasks: Vec<_> = (0..65)
            .map(|index| task(index + 1, &format!("delta-{index}")))
            .collect();
        let proposal = propose_shared_delta(&tasks, caps(64)).unwrap();
        assert_eq!(proposal.shared_delta_candidates.len(), 1);
        assert_eq!(proposal.shared_delta_candidates[0].task_ids.len(), 64);
        assert_eq!(proposal.baseline_tasks.len(), 1);
        assert_eq!(
            proposal.baseline_tasks[0].reason,
            BaselineReason::NoCompatiblePeer
        );
    }

    #[test]
    fn resource_pressure_splits_or_falls_back_instead_of_overcommitting() {
        let mut local_caps = caps(64);
        local_caps.group_resource_caps.memory_bytes = 2;
        let proposal =
            propose_shared_delta(&[task(1, "d1"), task(2, "d2"), task(3, "d3")], local_caps)
                .unwrap();
        assert_eq!(proposal.shared_delta_candidates.len(), 1);
        assert_eq!(proposal.shared_delta_candidates[0].task_ids, vec![1, 2]);
        assert_eq!(proposal.baseline_tasks.len(), 1);
    }

    #[test]
    fn duplicate_task_identity_fails_closed() {
        let result = propose_shared_delta(&[task(7, "d1"), task(7, "d2")], caps(64));
        assert_eq!(result, Err(PolicyRejectReason::DuplicateTaskId));
    }
}
