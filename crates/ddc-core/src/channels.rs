use crate::ComputeId;
use std::collections::BTreeMap;

/// One logical compute channel represented as shared state plus divergence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelDescriptor {
    pub logical_id: u32,
    pub shared_state: ComputeId,
    pub delta: ComputeId,
}

/// Group channels only when their shared-state identity is exactly equal.
pub fn group_by_shared_state(channels: &[ChannelDescriptor]) -> BTreeMap<ComputeId, Vec<u32>> {
    let mut groups = BTreeMap::<ComputeId, Vec<u32>>::new();
    for channel in channels {
        groups
            .entry(channel.shared_state)
            .or_default()
            .push(channel.logical_id);
    }
    groups
}

/// Exact work accounting for a simple shared-base + per-channel-delta model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkEstimate {
    pub baseline_units: u128,
    pub shared_units: u128,
}

impl WorkEstimate {
    pub fn leverage_ratio(self) -> f64 {
        if self.shared_units == 0 {
            return 1.0;
        }
        self.baseline_units as f64 / self.shared_units as f64
    }
}

pub fn estimate_shared_delta_work(
    channels: u64,
    shared_units: u64,
    delta_units_per_channel: u64,
) -> WorkEstimate {
    let channels = channels as u128;
    let shared = shared_units as u128;
    let delta = delta_units_per_channel as u128;

    WorkEstimate {
        baseline_units: channels * (shared + delta),
        shared_units: shared + channels * delta,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(label: &str) -> ComputeId {
        ComputeId::derive("channel-test", &[label.as_bytes()])
    }

    #[test]
    fn groups_only_identical_shared_state() {
        let shared = id("shared");
        let other = id("other");
        let channels = [
            ChannelDescriptor {
                logical_id: 1,
                shared_state: shared,
                delta: id("d1"),
            },
            ChannelDescriptor {
                logical_id: 2,
                shared_state: shared,
                delta: id("d2"),
            },
            ChannelDescriptor {
                logical_id: 3,
                shared_state: other,
                delta: id("d3"),
            },
        ];
        let groups = group_by_shared_state(&channels);
        assert_eq!(groups.get(&shared), Some(&vec![1, 2]));
        assert_eq!(groups.get(&other), Some(&vec![3]));
    }

    #[test]
    fn work_estimate_matches_definition() {
        let estimate = estimate_shared_delta_work(16, 1_000, 10);
        assert_eq!(estimate.baseline_units, 16_160);
        assert_eq!(estimate.shared_units, 1_160);
        assert!(estimate.leverage_ratio() > 13.9);
    }
}
