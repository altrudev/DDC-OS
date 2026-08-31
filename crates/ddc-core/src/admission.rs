use crate::{ComputeId, ResourceVector};
use std::collections::BTreeSet;

/// Named capabilities visible at the public DDC-OS boundary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthoritySet(BTreeSet<String>);

impl AuthoritySet {
    pub fn new<I, S>(items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self(items.into_iter().map(Into::into).collect())
    }

    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.0.is_subset(&other.0)
    }

    /// Deterministic structural identity of the exact authority set.
    ///
    /// BTreeSet ordering plus explicit length framing makes this stable and
    /// prevents ambiguous concatenation. The hash is an identity, not an
    /// authorization token.
    pub fn identity(&self) -> ComputeId {
        let mut bytes = Vec::new();
        for capability in &self.0 {
            let raw = capability.as_bytes();
            bytes.extend_from_slice(&(raw.len() as u64).to_le_bytes());
            bytes.extend_from_slice(raw);
        }
        ComputeId::derive("authority-set-v0.2", &[bytes.as_slice()])
    }
}

/// Canonical identity of an ordered exact dependency list.
pub fn dependency_state_id(dependencies: &[ComputeId]) -> ComputeId {
    let mut bytes = Vec::with_capacity(dependencies.len() * 32);
    for dependency in dependencies {
        bytes.extend_from_slice(dependency.as_bytes());
    }
    ComputeId::derive("dependency-state-v0.1", &[bytes.as_slice()])
}

/// Structural evidence supplied to the v0.1 admission gate.
///
/// v0.1 deliberately accepts only exact output-byte equivalence and exact
/// dependency identity. It does not accept caller-supplied "verified" flags.
pub struct AdmissionInput<'a> {
    pub baseline_output: &'a [u8],
    pub candidate_output: &'a [u8],
    pub baseline_dependencies: &'a [ComputeId],
    pub candidate_dependencies: &'a [ComputeId],
    pub baseline_authority: &'a AuthoritySet,
    pub candidate_authority: &'a AuthoritySet,
    pub candidate_resources: ResourceVector,
    pub resource_caps: ResourceVector,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    OutputMismatch,
    DependencyStateMismatch,
    AuthorityExpansion,
    ResourceCapExceeded,
}

/// Opaque evidence that the public v0.1 gate admitted an exact candidate.
///
/// This permit authorizes use by other DDC-OS v0.1 components such as the
/// verified-result store. It does not grant permission to commit external
/// side effects.
#[derive(Debug)]
pub struct AdmissionPermit {
    pub(crate) output_id: ComputeId,
    pub(crate) dependency_state: ComputeId,
}

impl AdmissionPermit {
    pub fn output_id(&self) -> ComputeId {
        self.output_id
    }

    pub fn dependency_state(&self) -> ComputeId {
        self.dependency_state
    }
}

/// Fail-closed exact admission gate.
///
/// Performance scoring is deliberately separate. Passing this function means
/// only that the candidate is structurally eligible for later selection/reuse.
pub fn admit_exact(input: &AdmissionInput<'_>) -> Result<AdmissionPermit, RejectReason> {
    if input.baseline_output != input.candidate_output {
        return Err(RejectReason::OutputMismatch);
    }

    let baseline_state = dependency_state_id(input.baseline_dependencies);
    let candidate_state = dependency_state_id(input.candidate_dependencies);
    if baseline_state != candidate_state {
        return Err(RejectReason::DependencyStateMismatch);
    }

    if !input.candidate_authority.is_subset_of(input.baseline_authority) {
        return Err(RejectReason::AuthorityExpansion);
    }

    if !input.candidate_resources.within(input.resource_caps) {
        return Err(RejectReason::ResourceCapExceeded);
    }

    Ok(AdmissionPermit {
        output_id: ComputeId::derive("admitted-output-v0.1", &[input.candidate_output]),
        dependency_state: candidate_state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(label: &str) -> ComputeId {
        ComputeId::derive("admission-test", &[label.as_bytes()])
    }

    fn resources() -> (ResourceVector, ResourceVector) {
        (
            ResourceVector {
                cpu_work_units: 10,
                memory_bytes: 10,
                io_bytes: 10,
                transport_bytes: 10,
            },
            ResourceVector {
                cpu_work_units: 20,
                memory_bytes: 20,
                io_bytes: 20,
                transport_bytes: 20,
            },
        )
    }

    #[test]
    fn authority_identity_is_order_independent_but_membership_sensitive() {
        let a = AuthoritySet::new(["b", "a"]);
        let b = AuthoritySet::new(["a", "b"]);
        let c = AuthoritySet::new(["a", "c"]);
        assert_eq!(a.identity(), b.identity());
        assert_ne!(a.identity(), c.identity());
    }

    #[test]
    fn admits_exact_candidate_without_trust_flags() {
        let dependency = [id("dep")];
        let baseline_authority = AuthoritySet::new(["capability-a"]);
        let candidate_authority = AuthoritySet::new(["capability-a"]);
        let (candidate_resources, resource_caps) = resources();
        let input = AdmissionInput {
            baseline_output: b"same-result",
            candidate_output: b"same-result",
            baseline_dependencies: &dependency,
            candidate_dependencies: &dependency,
            baseline_authority: &baseline_authority,
            candidate_authority: &candidate_authority,
            candidate_resources,
            resource_caps,
        };

        assert!(admit_exact(&input).is_ok());
    }

    #[test]
    fn rejects_output_mismatch() {
        let dependency = [id("dep")];
        let authority = AuthoritySet::new(["capability-a"]);
        let (candidate_resources, resource_caps) = resources();
        let input = AdmissionInput {
            baseline_output: b"baseline",
            candidate_output: b"different",
            baseline_dependencies: &dependency,
            candidate_dependencies: &dependency,
            baseline_authority: &authority,
            candidate_authority: &authority,
            candidate_resources,
            resource_caps,
        };

        assert!(matches!(admit_exact(&input), Err(RejectReason::OutputMismatch)));
    }

    #[test]
    fn rejects_dependency_state_mismatch() {
        let baseline_dependency = [id("a")];
        let candidate_dependency = [id("b")];
        let authority = AuthoritySet::new(["capability-a"]);
        let (candidate_resources, resource_caps) = resources();
        let input = AdmissionInput {
            baseline_output: b"same-result",
            candidate_output: b"same-result",
            baseline_dependencies: &baseline_dependency,
            candidate_dependencies: &candidate_dependency,
            baseline_authority: &authority,
            candidate_authority: &authority,
            candidate_resources,
            resource_caps,
        };

        assert!(matches!(
            admit_exact(&input),
            Err(RejectReason::DependencyStateMismatch)
        ));
    }

    #[test]
    fn rejects_capability_expansion() {
        let dependency = [id("dep")];
        let baseline_authority = AuthoritySet::new(["capability-a"]);
        let candidate_authority = AuthoritySet::new(["capability-a", "capability-b"]);
        let (candidate_resources, resource_caps) = resources();
        let input = AdmissionInput {
            baseline_output: b"same-result",
            candidate_output: b"same-result",
            baseline_dependencies: &dependency,
            candidate_dependencies: &dependency,
            baseline_authority: &baseline_authority,
            candidate_authority: &candidate_authority,
            candidate_resources,
            resource_caps,
        };

        assert!(matches!(
            admit_exact(&input),
            Err(RejectReason::AuthorityExpansion)
        ));
    }
}
