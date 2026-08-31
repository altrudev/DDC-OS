# DDC-OS Architecture v0.2

## Goal

Increase useful throughput on existing hardware by eliminating duplicated work before attempting lower-level hardware acceleration.

The architecture follows:

> **IDENTIFY → SHARE → DELTA → PACK → VERIFY**

## Layer model

1. **Linux compatibility substrate** — drivers, filesystems, networking, device support.
2. **DDC observation layer** — workload identity, dependency observation, security-context observation, resource accounting.
3. **DDC OS policy layer** — discovers optimization candidates but does not itself authorize kernel-control changes.
4. **DDC compute fabric** — verified-result reuse, shared-state groups, delta execution, batching/packing.
5. **DDC governor boundary** — semantic, authority, resource, provenance and commit-state admission.
6. **DDC scheduler integration** — initially user-space only; later sched_ext canaries.
7. **DDC desktop/compositor** — later milestone after compute gains are demonstrated.

Linux is retained initially because replacing mature device support would add risk without proving the compute hypothesis.

## Phase A — user-space compute proof

No scheduler replacement. No memory-policy writes. No privileged system changes.

Deliverables:

- deterministic compute identity;
- exact dependency-addressed result reuse;
- shared-state channel grouping;
- exact shared-base + delta benchmark at 1, 2, 4, 8, 16, 32 and 64 logical channels;
- resource and correctness measurements;
- fail-closed public admission gate.

## Phase A2 — OS-native observation and policy proposal

This is the first step toward putting DDC into the operating system itself without granting it kernel authority.

Deliverables:

- an OS-visible execution descriptor;
- exact security-context binding for candidate grouping;
- Linux self-observation of effective principal, namespaces, LSM label, seccomp/no-new-privs state and Linux capability state;
- a hard v0.2 group ceiling of 64;
- overflow-safe aggregate resource planning;
- fail-closed handling for duplicate identity, resource pressure, cross-principal, cross-isolation and authority mismatch;
- observation-only Linux probe with `kernel_writes=0`.

Only known-pure DDC-native computations are candidate-eligible. Unknown, legacy, read-only external and side-effecting workloads remain on the baseline path.

The policy output is a **candidate proposal**, not permission to run optimized code and not a scheduler command.

See [`OS_NATIVE_POLICY.md`](OS_NATIVE_POLICY.md).

## Phase B — shadow execution

Before any DDC candidate affects real scheduling or memory behavior:

- run baseline and candidate independently;
- compare exact observable results and exact dependency state;
- measure full resource cost including optimization overhead;
- inject stale state, malformed metadata, resource pressure and candidate termination;
- discard the candidate on any mismatch or uncertain state.

No externally visible speculative side effect may commit during this phase.

## Phase C — persistent compute memory

Add an on-disk content-addressed artifact store with:

- atomic writes;
- checksummed records;
- exact dependency lists;
- versioned format;
- corruption detection;
- bounded storage policy;
- explicit invalidation.

A corrupt or stale entry is a cache miss, never authority to synthesize a result.

## Phase D — contained userspace canary

Selected DDC-native pure workloads may be exercised under explicit kernel-enforced containment such as cgroup v2 ceilings.

The baseline implementation remains immediately available. Resource estimates from the policy layer are never treated as enforcement by themselves.

Reference: https://docs.kernel.org/admin-guide/cgroup-v2.html

## Phase E — scheduler canary

Only after the earlier phases pass regression do we introduce Linux `sched_ext`.

DDC-OS should begin with partial/canary scheduling, preserving the normal Linux fair scheduler for the rest of the system. The kernel's sched_ext interface can be enabled/disabled dynamically and falls back when the BPF scheduler errors or stalls. Its API has no stability guarantee between kernel versions, so DDC-OS must capability-detect and version-test rather than assume a fixed ABI.

Reference: https://docs.kernel.org/scheduler/sched-ext.html

Initial scheduler policy remains conservative: shared-state metadata is a placement/co-scheduling hint, not permission to alter program semantics.

Cross-process observation must also use a stable process identity. Plain `/proc/<pid>` observation followed by later action is insufficient because PID reuse and time-of-check/time-of-use races could bind policy to the wrong task. A future adapter must use pidfd plus revalidation or a stronger kernel mechanism.

## Phase F — memory observation

Use DAMON first as a read-only observation source for hot/cold access patterns. Do not let DDC-OS issue memory-management actions until measurement overhead and prediction quality are characterized.

Reference: https://docs.kernel.org/mm/damon/index.html

Only later may bounded, reversible memory policies be evaluated through the normal DDC gates.

## Phase G — memory-policy canary

If observation data demonstrates a worthwhile opportunity, memory-policy writes receive an independent DDC transition with rollback, pressure, swap, I/O and latency tests. A CPU win that creates damaging memory or I/O pressure is rejected.

## Phase H — desktop

After the compute substrate has demonstrated repeatable gains, build the DDC compositor/shell.

The desktop should expose persistent workspaces and computation-aware resume while preserving compatibility with existing Wayland/XWayland applications during migration.

The GUI is not allowed to become the benchmark target: visual polish cannot substitute for measurable compute gains.

## Non-goals for v0.2

- claiming exponential improvement for arbitrary workloads;
- replacing the Linux kernel;
- system-wide experimental scheduling;
- speculative external side effects;
- fuzzy cache equivalence;
- arbitrary cross-process sharing;
- trusting application claims about purity or security context;
- AI-dependent basic desktop operation;
- hidden benchmark shortcuts;
- performance gains that exceed resource/safety limits elsewhere.

## Primary metric

DDC-OS tracks **Computational Leverage Ratio (CLR)**:

`CLR = baseline work units / DDC executed work units`

CLR is workload-specific and must always be reported with its workload definition. It is not a claim that CPU clock speed or physical channel capacity increased.
