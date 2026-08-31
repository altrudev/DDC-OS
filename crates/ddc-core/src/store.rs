use crate::ComputeId;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedArtifact {
    dependencies: Vec<ComputeId>,
    output: Vec<u8>,
}

/// Minimal exact-match store for already verified results.
///
/// v0.1 deliberately refuses fuzzy dependency matching. Broader equivalence
/// belongs in a later layer with its own proof and regression suite.
#[derive(Default)]
pub struct VerifiedStore {
    entries: HashMap<ComputeId, VerifiedArtifact>,
}

impl VerifiedStore {
    pub fn insert_verified(
        &mut self,
        id: ComputeId,
        dependencies: Vec<ComputeId>,
        output: Vec<u8>,
    ) {
        self.entries.insert(
            id,
            VerifiedArtifact {
                dependencies,
                output,
            },
        );
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

    fn id(label: &str) -> ComputeId {
        ComputeId::derive("store-test", &[label.as_bytes()])
    }

    #[test]
    fn reuse_requires_exact_dependency_identity() {
        let mut store = VerifiedStore::default();
        let work = id("work");
        let a = id("a");
        let b = id("b");
        store.insert_verified(work, vec![a], b"result".to_vec());

        assert_eq!(store.get_if_current(work, &[a]), Some(b"result".as_slice()));
        assert_eq!(store.get_if_current(work, &[b]), None);
    }
}
