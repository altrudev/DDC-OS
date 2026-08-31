# DDC-OS Safety Gates

These are public engineering gates, not a disclosure of proprietary DDC internals.

No optimization is considered canonical merely because it is faster.

## Gate 0 — Exact baseline

Before optimization, freeze:

- workload definition;
- input/dependency identity;
- expected observable output;
- authority boundary;
- resource measurement method;
- fallback implementation.

A benchmark without a stable baseline is evidence of nothing.

## Gate 1 — Semantic equivalence

Candidate and baseline must produce equivalent observable results for the accepted workload domain.

Any mismatch is a hard rejection. A speedup cannot compensate for incorrect output.

## Gate 2 — Exact-state provenance

Reusable work must be bound to the exact state that produced it. A dependency change invalidates reuse unless a separately proven equivalence rule says otherwise.

v0.1 permits exact identity reuse only.

## Gate 3 — Authority containment

Candidate authority must be a subset of or equal to baseline authority. Optimization cannot create new permissions.

## Gate 4 — Resource containment

Measure at least:

- CPU work/time;
- memory peak;
- storage I/O;
- transport/network bytes where relevant;
- wall-clock latency;
- optimization bookkeeping overhead.

A candidate that moves unacceptable pressure from one resource to another is rejected even if one metric improves.

## Gate 5 — Commit isolation

Speculative execution may calculate, cache, and verify, but must not commit externally visible effects before admission.

## Gate 6 — Failure injection

Before a candidate controls system-wide behavior, test:

- corrupted/missing cache entries;
- stale dependency identities;
- abrupt optimizer termination;
- resource-cap exhaustion;
- malformed metadata;
- partial state;
- fallback activation.

Failure must return control to a known-safe baseline rather than strand the system in an intermediate optimization state.

## Gate 7 — Canary scope

Kernel-affecting mechanisms begin in the smallest reversible scope available.

For sched_ext this means preferring partial switching/canary tasks before system-wide scheduling. The Linux kernel documentation explicitly supports dynamic enable/disable and fallback to the fair scheduler when sched_ext errors or stalls; DDC-OS treats that fallback as a required safety property, not merely a convenience.

## Gate 8 — Promotion

Only after complete regression, repeatable benchmark evidence, failure tests, and a fresh DDC review may an optimization move from experimental to default-on.

Promotion is version- and state-specific. A later code change supersedes prior approval until the affected gates pass again.
