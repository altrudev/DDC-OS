# DDC-OS Architecture v0.1

## Goal

Increase useful throughput on existing hardware by eliminating duplicated work before attempting lower-level hardware acceleration.

The architecture follows:

> **IDENTIFY → SHARE → DELTA → PACK → VERIFY**

## Layer model

1. **Linux compatibility substrate** — drivers, filesystems, networking, device support.
2. **DDC observation layer** — workload identity, dependency observation, resource accounting.
3. **DDC compute fabric** — verified-result reuse, shared-state groups, delta execution, batching/packing.
4. **DDC governor boundary** — semantic, authority, resource, provenance and commit-state admission.
5. **DDC scheduler integration** — initially user-space only; later sched_ext canaries.
6. **DDC desktop/compositor** — later milestone after compute gains are demonstrated.

Linux is retained initially because replacing mature device support would add risk without proving the compute hypothesis.

## Phase A — user-space proof

No scheduler replacement. No memory-policy writes. No privileged system changes.

Deliverables:

- deterministic compute identity;
- exact dependency-addressed result reuse;
- shared-state channel grouping;
- exact shared-base + delta benchmark at 1, 2, 4, 8 and 16 logical channels;
- resource and correctness measurements;
- fail-closed public admission gate.

## Phase B — persistent compute memory

Add an on-disk content-addressed artifact store with:

- atomic writes;
- checksummed records;
- exact dependency lists;
- versioned format;
- corruption detection;
- bounded storage policy;
- explicit invalidation.

A corrupt or stale entry is a cache miss, never authority to synthesize a result.

## Phase C — scheduler canary

Only after Phases A/B pass regression do we introduce Linux `sched_ext`.

DDC-OS should begin with partial/canary scheduling, preserving the normal Linux fair scheduler for the rest of the system. The kernel's sched_ext interface can be enabled/disabled dynamically and falls back when the BPF scheduler errors or stalls. Its API has no stability guarantee between kernel versions, so DDC-OS must capability-detect and version-test rather than assume a fixed ABI.

Reference: https://docs.kernel.org/scheduler/sched-ext.html

Initial scheduler policy should remain conservative: use shared-state metadata as a hint for placement/co-scheduling, not as permission to alter program semantics.

## Phase D — memory observation

Use DAMON first as a read-only observation source for hot/cold access patterns. Do not let DDC-OS issue memory-management actions until measurement overhead and prediction quality are characterized.

Reference: https://docs.kernel.org/mm/damon/index.html

Only later may bounded, reversible memory policies be evaluated through the normal DDC gates.

## Phase E — resource enforcement

Use cgroup v2 as the underlying Linux enforcement mechanism for bounded experiments and workloads. The DDC governor remains the policy boundary; cgroups provide kernel-enforced containment for CPU, memory and I/O where supported.

Reference: https://docs.kernel.org/admin-guide/cgroup-v2.html

## Phase F — desktop

After the compute substrate has demonstrated repeatable gains, build the DDC compositor/shell.

The desktop should expose persistent workspaces and computation-aware resume while preserving compatibility with existing Wayland/XWayland applications during migration.

The GUI is not allowed to become the benchmark target: visual polish cannot substitute for measurable compute gains.

## Non-goals for v0.1

- claiming exponential improvement for arbitrary workloads;
- replacing the Linux kernel;
- system-wide experimental scheduling;
- speculative external side effects;
- fuzzy cache equivalence;
- AI-dependent basic desktop operation;
- hidden benchmark shortcuts;
- performance gains that exceed resource/safety limits elsewhere.

## Primary metric

DDC-OS tracks **Computational Leverage Ratio (CLR)**:

`CLR = baseline work units / DDC executed work units`

CLR is workload-specific and must always be reported with its workload definition. It is not a claim that CPU clock speed or physical channel capacity increased.
