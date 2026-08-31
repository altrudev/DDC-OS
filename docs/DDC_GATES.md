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

v0.1/v0.2 permit exact identity reuse only.

## Gate 3 — Authority containment

Candidate authority must be a subset of or equal to baseline authority. Optimization cannot create new permissions.

## Gate 3A — OS-observed security binding

OS-native optimization candidates must be bound to security facts observed by the trusted OS adapter, not to application-supplied claims such as `same_user`, `pure=true`, or `same_security_domain`.

For the v0.2 Linux observation slice, the adapter binds candidate identity to the current process's principal, Linux capability state, namespace identity, LSM label, seccomp/no-new-privs metadata, and related process-security state.

v0.2 observes only itself. Cross-process policy is blocked until:

- observation is bound to a stable process identity rather than a reusable PID;
- time-of-check/time-of-use revalidation exists;
- seccomp/LSM equivalence has stronger evidence than superficial procfs fields, or uncertainty returns the work to baseline.

A traced process is not candidate-eligible in v0.2.

## Gate 4 — Resource containment

Measure at least:

- CPU work/time;
- memory peak;
- storage I/O;
- transport/network bytes where relevant;
- wall-clock latency;
- optimization bookkeeping overhead.

Candidate aggregation arithmetic must be overflow-safe. Overflow or cap pressure returns affected work to baseline.

A candidate that moves unacceptable pressure from one resource to another is rejected even if one metric improves.

Planning estimates are not enforcement. Before activation, use kernel-enforced resource ceilings where applicable.

## Gate 5 — Commit isolation

Speculative execution may calculate, cache, and verify, but must not commit externally visible effects before admission.

Unknown, legacy, read-only external, and side-effecting work remain baseline-only unless a later version establishes a narrower proof.

## Gate 6 — Failure injection

Before a candidate controls system-wide behavior, test:

- corrupted/missing cache entries;
- stale dependency identities;
- abrupt optimizer termination;
- resource-cap exhaustion;
- arithmetic overflow;
- malformed metadata;
- duplicate task identity;
- incomplete security observation;
- PID/process identity change during observation;
- partial state;
- fallback activation.

Failure must return control to a known-safe baseline rather than strand the system in an intermediate optimization state.

## Gate 7 — Canary scope

Kernel-affecting mechanisms begin in the smallest reversible scope available.

For sched_ext this means preferring partial switching/canary tasks before system-wide scheduling. The Linux kernel documentation explicitly supports dynamic enable/disable and fallback to the fair scheduler when sched_ext errors or stalls; DDC-OS treats that fallback as a required safety property, not merely a convenience.

The v0.2 OS-policy layer produces candidate proposals only. It has no scheduler or memory-policy write authority.

## Gate 8 — Promotion

Only after complete regression, repeatable benchmark evidence, failure tests, exact tested SHA, and a fresh DDC review may an optimization move from experimental to default-on.

Promotion is version- and state-specific. A later code change supersedes prior approval until the affected gates pass again.
