use crate::admission::{dependency_state_id, AdmissionPermit};
use crate::ComputeId;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedArtifact {
    dependencies: Vec<ComputeId>,
    output: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreRejectReason {
    PermitOutputMismatch,
    PermitDependencyMismatch,
}

/// Minimal exact-match store for admitted results.
///
/// A caller cannot mark arbitrary bytes as verified. Insertion requires an
/// opaque AdmissionPermit produced by the public exact admission gate, and the
/// store re-checks that the permit is bound to the supplied output/dependencies.
#[derive(Default)]
pub struct VerifiedStore {
    entries: HashMap<ComputeId, VerifiedArtifact>,
}

impl VerifiedStore {
    pub fn insert_admitted(
        &mut self,
        permit: &AdmissionPermit,
        dependencies: Vec<ComputeId>,
        output: Vec<u8>,
    ) -> Result<ComputeId, StoreRejectReason> {
        let output_id = ComputeId::derive("admitted-output-v0.1", &[output.as_slice()]);
        if output_id != permit.output_id {
            return Err(StoreRejectReason::PermitOutputMismatch);
        }

        let dependency_state = dependency_state_id(&dependencies);
        if dependency_state != permit.dependency_state {
            return Err(StoreRejectReason::PermitDependencyMismatch);
        }

        let artifact_id = ComputeId::derive(
            "verified-artifact-v0.1",
            &[
                permit.output_id.as_bytes(),
                permit.dependency_state.as_bytes(),
            ],
        );

        self.entries.insert(
            artifact_id,
            VerifiedArtifact {
                dependencies,
                output,
            },
        );
        Ok(artifact_id)
    }

    pub fn get_if_current(
        &self,
        id: ComputeId,
        current_dependencies: &[ComputeId],
    ) -> Option<&[u8]> {
        let artifact = self.entries.get(&id)?;
        if artifact.dependencies == current_dependencies {
            Some(artifact.output.as_slice())
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{admit_exact, AdmissionInput, AuthoritySet};
    use crate::ResourceVector;

    fn id(label: &str) -> ComputeId {
        ComputeId::derive("store-test", &[label.as_bytes()])
    }

    fn permit_for(output: &[u8], dependency: ComputeId) -> AdmissionPermit {
        let dependencies = [dependency];
        let authority = AuthoritySet::new(["capability-a"]);
        let input = AdmissionInput {
            baseline_output: output,
            candidate_output: output,
            baseline_dependencies: &dependencies,
            candidate_dependencies: &dependencies,
            baseline_authority: &authority,
            candidate_authority: &authority,
            candidate_resources: ResourceVector::default(),
            resource_caps: ResourceVector::default(),
        };
        admit_exact(&input).expect("exact candidate should be admitted")
    }

    #[test]
    fn admitted_result_reuse_requires_current_dependencies() {
        let mut store = VerifiedStore::default();
        let a = id("a");
        let b = id("b");
        let permit = permit_for(b"result", a);
        let artifact = store
            .insert_admitted(&permit, vec![a], b"result".to_vec())
            .expect("permit is bound to result and dependency");

        assert_eq!(
            store.get_if_current(artifact, &[a]),
            Some(b"result".as_slice())
        );
        assert_eq!(store.get_if_current(artifact, &[b]), None);
    }

    #[test]
    fn permit_cannot_be_reused_for_different_output() {
        let mut store = VerifiedStore::default();
        let dependency = id("a");
        let permit = permit_for(b"approved", dependency);
        let result = store.insert_admitted(&permit, vec![dependency], b"other".to_vec());
        assert_eq!(result, Err(StoreRejectReason::PermitOutputMismatch));
    }

    #[test]
    fn permit_cannot_be_reused_for_different_dependency_state() {
        let mut store = VerifiedStore::default();
        let a = id("a");
        let b = id("b");
        let permit = permit_for(b"result", a);
        let result = store.insert_admitted(&permit, vec![b], b"result".to_vec());
        assert_eq!(result, Err(StoreRejectReason::PermitDependencyMismatch));
    }
}
