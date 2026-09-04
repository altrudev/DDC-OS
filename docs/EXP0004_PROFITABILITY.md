# EXP-0004 — Governed profitability / overlap sweep

## Purpose

Measure where DDC-OS v0.3 becomes net-profitable as the fraction of repeated work increases, while including the public governance path in the timed DDC lane.

EXP-0004 is a synthetic crossover experiment. It does **not** claim an end-to-end operating-system speedup.

## Fixed workload

Each logical channel processes `262,144` 64-bit words. The experiment varies how many of those words are identical shared work versus per-channel delta work.

Channel counts:

`1, 2, 4, 8, 16, 32, 64`

Overlap sweep, in percent:

`0, 0.01, 0.02, 0.05, 0.10, 0.25, 0.50, 1, 2, 5, 10, 20, 40, 60, 80, 90, 95, 99, 100`

Each point uses 30 samples. The order of the three timed lanes rotates across six permutations to reduce systematic lane-order, thermal, and frequency bias.

## Timed lanes

### Baseline

Recompute the shared portion independently for every channel, then compute that channel's delta.

### Raw DDC

Compute the shared portion once, compute every channel delta, and verify exact output equality against the precomputed expected result.

### Governed DDC

Time the following public v0.3 path:

1. OS-policy candidate planning with `propose_shared_delta`;
2. proposal materialization by clone for every admitted task;
3. Radial + dimensional transition evaluation;
4. explicit checks that Frequency is non-authoritative and Radial does not authorize execution;
5. shared/delta execution when the whole family remains shadow-eligible, otherwise deterministic baseline fallback;
6. exact result verification against the expected output.

For zero overlap, descriptors intentionally have distinct shared-state identities and therefore fall back. A one-channel case also cannot form a sharing family. These are negative controls.

## Excluded from the timed region

- Linux `/proc` observation;
- workload/data generation;
- initial construction of descriptors and dimensional transition proposals.

These exclusions must be stated when interpreting results. A later experiment is required before making end-to-end OS-overhead claims.

## Outputs

For each channel-count / overlap point the benchmark reports p50 and p95 latency for all three lanes, raw and governed speedup ratios, exact verification status, and whether governed p50 beats baseline p50.

For each channel count it also prints the first sampled overlap point at which governed DDC becomes profitable. This is an empirical grid threshold, **not** a universal constant and not yet an OS policy rule.

## Safety / authority

EXP-0004 remains user-space only. Radial and Frequency are evidence/observation inputs, not execution authority. No kernel scheduling, cgroup, memory, or other privileged state is changed by this benchmark.
