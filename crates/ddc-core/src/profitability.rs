#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfitabilityState {
    Baseline,
    ShadowCandidate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfitabilityAction {
    StayBaseline,
    EnterShadowCandidate,
    RetainShadowCandidate,
    ExitToBaseline,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfitabilityReason {
    Eligible,
    NoShareablePeer,
    MedianBelowThreshold,
    LowerQuartileBelowThreshold,
    ProfitableEpochsBelowThreshold,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfitabilityRejectReason {
    InvalidPolicy,
    InvalidEvidence,
}

/// Integer confidence evidence for a potential optimization.
///
/// Speedups use basis points where 10_000 == 1.00x and 10_500 == 1.05x.
/// The evidence is observational only; it cannot authorize execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfitabilityEvidence {
    pub candidate_count: usize,
    pub median_speedup_bp: u32,
    pub lower_quartile_speedup_bp: u32,
    pub profitable_epochs: usize,
    pub total_epochs: usize,
}

impl ProfitabilityEvidence {
    pub const fn authorizes_execution(self) -> bool {
        false
    }

    fn is_valid(self) -> bool {
        self.total_epochs > 0 && self.profitable_epochs <= self.total_epochs
    }
}

/// Configurable confidence and hysteresis thresholds.
///
/// These values are policy inputs, not universal DDC constants. The public
/// primitive requires entry thresholds to be at least as strict as retention
/// thresholds so that a caller cannot accidentally invert hysteresis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfitabilityPolicy {
    pub enter_median_speedup_bp: u32,
    pub enter_lower_quartile_speedup_bp: u32,
    pub enter_profitable_epochs: usize,
    pub retain_median_speedup_bp: u32,
    pub retain_lower_quartile_speedup_bp: u32,
    pub retain_profitable_epochs: usize,
}

impl ProfitabilityPolicy {
    fn is_valid(self) -> bool {
        self.enter_median_speedup_bp >= self.retain_median_speedup_bp
            && self.enter_lower_quartile_speedup_bp >= self.retain_lower_quartile_speedup_bp
            && self.enter_profitable_epochs >= self.retain_profitable_epochs
            && self.enter_profitable_epochs > 0
            && self.retain_profitable_epochs > 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfitabilityDecision {
    pub previous: ProfitabilityState,
    pub next: ProfitabilityState,
    pub action: ProfitabilityAction,
    pub reason: ProfitabilityReason,
}

impl ProfitabilityDecision {
    /// Profitability can select a candidate mode for later governed evaluation,
    /// but it never grants execution authority.
    pub const fn authorizes_execution(self) -> bool {
        false
    }
}

fn qualifies(
    evidence: ProfitabilityEvidence,
    median_threshold: u32,
    lower_quartile_threshold: u32,
    profitable_epochs_threshold: usize,
) -> Result<(), ProfitabilityReason> {
    if evidence.candidate_count < 2 {
        return Err(ProfitabilityReason::NoShareablePeer);
    }
    if evidence.median_speedup_bp < median_threshold {
        return Err(ProfitabilityReason::MedianBelowThreshold);
    }
    if evidence.lower_quartile_speedup_bp < lower_quartile_threshold {
        return Err(ProfitabilityReason::LowerQuartileBelowThreshold);
    }
    if evidence.profitable_epochs < profitable_epochs_threshold {
        return Err(ProfitabilityReason::ProfitableEpochsBelowThreshold);
    }
    Ok(())
}

/// Evaluate a public profitability recommendation with hysteresis.
///
/// This function does not inspect overlap percentages and does not authorize
/// execution. It consumes measured confidence evidence and recommends whether
/// a later shadow candidate should be entered, retained, or abandoned.
pub fn evaluate_profitability(
    previous: ProfitabilityState,
    evidence: ProfitabilityEvidence,
    policy: ProfitabilityPolicy,
) -> Result<ProfitabilityDecision, ProfitabilityRejectReason> {
    if !policy.is_valid() {
        return Err(ProfitabilityRejectReason::InvalidPolicy);
    }
    if !evidence.is_valid()
        || policy.enter_profitable_epochs > evidence.total_epochs
        || policy.retain_profitable_epochs > evidence.total_epochs
    {
        return Err(ProfitabilityRejectReason::InvalidEvidence);
    }

    let qualification = match previous {
        ProfitabilityState::Baseline => qualifies(
            evidence,
            policy.enter_median_speedup_bp,
            policy.enter_lower_quartile_speedup_bp,
            policy.enter_profitable_epochs,
        ),
        ProfitabilityState::ShadowCandidate => qualifies(
            evidence,
            policy.retain_median_speedup_bp,
            policy.retain_lower_quartile_speedup_bp,
            policy.retain_profitable_epochs,
        ),
    };

    Ok(match (previous, qualification) {
        (ProfitabilityState::Baseline, Ok(())) => ProfitabilityDecision {
            previous,
            next: ProfitabilityState::ShadowCandidate,
            action: ProfitabilityAction::EnterShadowCandidate,
            reason: ProfitabilityReason::Eligible,
        },
        (ProfitabilityState::Baseline, Err(reason)) => ProfitabilityDecision {
            previous,
            next: ProfitabilityState::Baseline,
            action: ProfitabilityAction::StayBaseline,
            reason,
        },
        (ProfitabilityState::ShadowCandidate, Ok(())) => ProfitabilityDecision {
            previous,
            next: ProfitabilityState::ShadowCandidate,
            action: ProfitabilityAction::RetainShadowCandidate,
            reason: ProfitabilityReason::Eligible,
        },
        (ProfitabilityState::ShadowCandidate, Err(reason)) => ProfitabilityDecision {
            previous,
            next: ProfitabilityState::Baseline,
            action: ProfitabilityAction::ExitToBaseline,
            reason,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ProfitabilityPolicy {
        ProfitabilityPolicy {
            enter_median_speedup_bp: 10_500,
            enter_lower_quartile_speedup_bp: 10_100,
            enter_profitable_epochs: 7,
            retain_median_speedup_bp: 10_000,
            retain_lower_quartile_speedup_bp: 9_800,
            retain_profitable_epochs: 5,
        }
    }

    fn evidence(median: u32, lower: u32, profitable: usize) -> ProfitabilityEvidence {
        ProfitabilityEvidence {
            candidate_count: 8,
            median_speedup_bp: median,
            lower_quartile_speedup_bp: lower,
            profitable_epochs: profitable,
            total_epochs: 9,
        }
    }

    #[test]
    fn strong_evidence_enters_shadow_candidate_but_never_authorizes() {
        let observed = evidence(10_600, 10_200, 9);
        assert!(!observed.authorizes_execution());
        let decision = evaluate_profitability(ProfitabilityState::Baseline, observed, policy())
            .expect("valid evidence");
        assert_eq!(decision.action, ProfitabilityAction::EnterShadowCandidate);
        assert_eq!(decision.next, ProfitabilityState::ShadowCandidate);
        assert!(!decision.authorizes_execution());
    }

    #[test]
    fn hysteresis_retains_evidence_that_is_too_weak_to_enter() {
        let observed = evidence(10_200, 10_000, 7);
        let from_baseline = evaluate_profitability(ProfitabilityState::Baseline, observed, policy())
            .expect("valid evidence");
        let from_shadow =
            evaluate_profitability(ProfitabilityState::ShadowCandidate, observed, policy())
                .expect("valid evidence");
        assert_eq!(from_baseline.action, ProfitabilityAction::StayBaseline);
        assert_eq!(from_shadow.action, ProfitabilityAction::RetainShadowCandidate);
    }

    #[test]
    fn falling_below_retention_exits_to_baseline() {
        let decision = evaluate_profitability(
            ProfitabilityState::ShadowCandidate,
            evidence(9_950, 9_700, 4),
            policy(),
        )
        .expect("valid evidence");
        assert_eq!(decision.action, ProfitabilityAction::ExitToBaseline);
        assert_eq!(decision.next, ProfitabilityState::Baseline);
    }

    #[test]
    fn single_candidate_never_enters() {
        let mut observed = evidence(20_000, 20_000, 9);
        observed.candidate_count = 1;
        let decision = evaluate_profitability(ProfitabilityState::Baseline, observed, policy())
            .expect("valid evidence");
        assert_eq!(decision.action, ProfitabilityAction::StayBaseline);
        assert_eq!(decision.reason, ProfitabilityReason::NoShareablePeer);
    }

    #[test]
    fn malformed_evidence_fails_closed() {
        let mut observed = evidence(10_600, 10_200, 9);
        observed.profitable_epochs = 10;
        assert_eq!(
            evaluate_profitability(ProfitabilityState::Baseline, observed, policy()),
            Err(ProfitabilityRejectReason::InvalidEvidence)
        );
    }

    #[test]
    fn inverted_hysteresis_policy_is_rejected() {
        let mut invalid = policy();
        invalid.enter_median_speedup_bp = 9_900;
        assert_eq!(
            evaluate_profitability(
                ProfitabilityState::Baseline,
                evidence(10_600, 10_200, 9),
                invalid,
            ),
            Err(ProfitabilityRejectReason::InvalidPolicy)
        );
    }
}
