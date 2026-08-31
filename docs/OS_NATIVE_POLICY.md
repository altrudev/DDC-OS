# DDC-OS OS-native policy — v0.2

This document defines the first safe step toward putting DDC into the operating system itself.

It is a public engineering contract, not a disclosure of proprietary DDC internals.

## What v0.2 does

v0.2 adds an OS-facing policy layer that can identify groups of work that are structurally eligible for later shared/delta execution.

The policy runs before scheduler placement conceptually, but **it does not control the scheduler**.

The transition is:

```text
OS observation
  -> execution descriptor
  -> DDC candidate detection
  -> shadow candidate only
  -> exact verification/admission later
  -> kernel influence still blocked
```

A candidate is not an authorization token.

## DDC decisions frozen for v0.2

### 1. Only known-pure computation may be grouped

Legacy processes, unknown work, read-only external work, and externally side-effecting work remain on baseline execution.

"Read-only" is not treated as pure because external state can change between observations.

### 2. Security and authority equivalence are structural

Sharing requires the same:

- executable identity;
- shared-state identity;
- exact shared dependency state;
- observed principal identity;
- observed isolation-context identity;
- exact OS-level authority identity;
- exact logical DDC/capsule authority identity.

The logical task authority remains separate from Linux process authority because multiple DDC-native tasks inside one process may intentionally hold different permissions.

A matching user id or matching process by itself is insufficient.

### 3. Linux security facts come from the OS adapter

The v0.2 Linux adapter reads its own procfs security state and derives identities from:

- all four Linux UID values (real, effective, saved-set and filesystem UID);
- all four Linux GID values (real, effective, saved-set and filesystem GID);
- supplementary groups;
- inheritable, permitted, effective, bounding and ambient Linux capability sets;
- LSM label;
- `NoNewPrivs`;
- seccomp mode and exposed seccomp filter count;
- tracer state;
- cgroup, IPC, mount, network, PID, time, user and UTS namespace identities, including child PID/time namespace identities.

A traced process is not candidate-eligible in v0.2.

The returned Linux snapshot is opaque outside the adapter.

Application-supplied "same security domain" flags are not accepted as evidence.

### 4. Cross-process observation is intentionally not implemented yet

Reading `/proc/<pid>` and later acting on that PID creates PID-reuse and time-of-check/time-of-use risk.

Before DDC-OS observes another process for an authoritative decision, the adapter must bind observation to a stable process identity, such as a pidfd plus state revalidation or a stronger kernel-level mechanism.

There is a second reason to remain conservative: procfs exposes seccomp mode and filter count, but not a complete cryptographic identity of the active filter program. Two different processes can therefore look superficially similar while being constrained by different filters. Before cross-process sharing is enabled, DDC-OS must obtain stronger kernel evidence for seccomp/LSM equivalence or treat that difference as non-shareable.

v0.2 therefore observes only the current process.

### 5. Group size is hard-capped at 64

`64` is an absolute v0.2 safety ceiling, not merely a benchmark parameter.

A larger compatible set is split; a leftover singleton returns to baseline. Raising this bound is a versioned DDC transition requiring new benchmark and failure evidence.

### 6. Resource arithmetic is overflow-safe

Candidate aggregation uses checked arithmetic. Overflow, cap pressure, or an oversized individual member returns affected work to baseline instead of overcommitting the machine.

Resource estimates are planning hints only. A future activation stage must pair them with kernel-enforced containment such as cgroup v2 ceilings.

### 7. Duplicate task identity fails the proposal

A duplicate task id causes the complete proposal operation to fail closed rather than risk double-accounting or ambiguous ownership.

## Linux probe

The `ddc-linux` crate includes an observation-only probe that:

1. reads the probe process's actual Linux security context;
2. constructs 64 synthetic tasks whose computation is explicitly known to be pure and whose logical DDC authority is explicit;
3. asks the DDC OS policy for candidate grouping;
4. requires one 64-member candidate and zero baseline tasks;
5. reports `kernel_writes=0`.

The probe does not alter scheduling, memory policy, namespaces, privileges, cgroups, sysctls, filesystems, or network configuration.

## Activation ladder

DDC-OS must move through these states in order:

### A — Observation only (current)

- derive OS security context;
- bind logical DDC/capsule authority;
- identify candidates;
- make no kernel-control changes.

### B — Shadow execution

- execute baseline and DDC candidate independently;
- compare exact observable output and dependency state;
- measure full resource vector;
- discard candidate on any mismatch.

### C — Contained userspace canary

- selected DDC-native pure workloads only;
- explicit cgroup resource ceilings;
- baseline fallback remains immediately available;
- no system-wide scheduler changes.

### D — Scheduler canary

Only after A-C pass repeatably:

- capability-detect `sched_ext`;
- use the smallest task scope;
- retain deterministic fair-scheduler fallback;
- inject stalls/crashes/resource pressure before promotion.

### E — Memory-policy canary

Only after observation data and benchmark evidence justify it:

- DAMON starts observation-only;
- any memory-policy write gets an independent DDC transition and rollback gate;
- system pressure, swap, I/O and latency are measured together.

### F — Default-on policy

Requires complete regression, repeatable target-hardware evidence, failure injection, exact tested SHA, and a fresh DDC review.

## Non-goals for v0.2

v0.2 does not:

- replace the Linux scheduler;
- hook syscalls;
- deduplicate arbitrary process memory;
- share results across OS or logical authority contexts;
- infer purity from application claims;
- execute speculative side effects;
- treat a candidate proposal as permission to run optimized code;
- raise the 64-channel ceiling automatically.

The governing rule remains: **optimization may reduce work, but it may not reduce assurance.**
