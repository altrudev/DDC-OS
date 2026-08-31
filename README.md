# DDC-OS

**DDC-OS** is an experimental computing system for extracting substantially more useful work from existing hardware by reducing duplicated computation, reusing verified state, grouping related work, and enforcing explicit safety/resource boundaries.

DDC-OS starts on Linux for hardware compatibility, but Linux is treated as a compatibility and device-support substrate rather than the final computing model.

## Core hypothesis

Conventional systems mostly optimize *where* and *how fast* work executes. DDC-OS also asks whether that work needs to execute at all.

The initial compute model is:

> **IDENTIFY → SHARE → DELTA → PACK → VERIFY**

The project explores five public primitives:

1. **Compute identity** — deterministic identities for reusable computations and dependencies.
2. **Shared execution** — identify common work across related logical channels.
3. **Delta execution** — recompute only invalidated state.
4. **Packed execution** — safely batch/vectorize compatible work when profitable.
5. **Verified optimization** — an optimization must preserve semantics, authority, and bounded resource behavior before it can be accepted.

## Safety model

DDC-OS v0.x is deliberately fail-safe:

- optimizations are opt-in and measurable;
- baseline execution remains available;
- an optimization may never expand application authority;
- CPU, memory, I/O, bandwidth and latency costs are explicit inputs to admission decisions;
- cached/reused work must be dependency-addressed and invalidated on relevant state change;
- speculative work cannot commit externally visible effects;
- experimental scheduling must have a deterministic fallback path;
- correctness wins over throughput.

The v0.1 public gate does **not** accept caller-supplied `verified=true` style claims. Exact candidate output and exact dependency state are compared structurally, and admitted cache writes require an opaque permit bound to those exact values.

## Public / private boundary

This repository is intended to be public.

It contains the **public DDC-OS contracts, architecture, benchmarks and implementations needed to build and test the operating system**. It does **not** require publication of proprietary DDC methodology, private scoring rules, confidential evidence, internal heuristics, or restricted assurance logic.

The public governor boundary is expressed as inputs, invariants and decisions. A conforming implementation may be open or proprietary as long as its observable contract is testable.

See:

- [`docs/PUBLIC_BOUNDARY.md`](docs/PUBLIC_BOUNDARY.md)
- [`docs/DDC_GATES.md`](docs/DDC_GATES.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

## v0.1 target

The first milestone is not a desktop theme or Linux distribution. It is a measurable compute substrate that can run beside normal Linux execution and answer one question:

> Can we perform the same verified workload with materially less total system work?

v0.1 will measure at minimum:

- wall-clock time;
- CPU time and retired work where available;
- peak memory;
- disk I/O;
- cache/reuse hit rate;
- invalidation rate;
- optimization overhead;
- logical-channel throughput at 1 / 2 / 4 / 8 / 16 channels;
- fallback/error rate;
- semantic equivalence failures (must remain zero for accepted results).

## First experiment

The current benchmark uses an exactly decomposable workload with one large shared base and a small per-channel delta. The baseline reprocesses the shared base for every logical channel; the DDC path processes the base once and only processes each channel's delta separately.

It tests logical channel counts of **1, 2, 4, 8 and 16** and hard-fails if baseline and DDC outputs differ.

On a Rust-capable host:

```bash
cargo test --workspace
cargo run -p ddc-bench --release
```

Optional workload sizing:

```bash
DDC_BENCH_BASE_WORDS=2000000 \
DDC_BENCH_DELTA_WORDS=4096 \
cargo run -p ddc-bench --release
```

The benchmark reports both measured wall-time speedup and **Computational Leverage Ratio (CLR)**. CLR is workload-specific and must not be represented as a physical increase in CPU frequency, core count, or channel capacity.

## Current gate status

| Gate | Status |
|---|---|
| Public/private disclosure boundary | PASS |
| Architecture and fallback rules | PASS |
| Structural exact-state admission design | PASS |
| No spoofable `verified=true` cache insertion | PASS |
| Source-level branch review | PASS |
| Rust compile/test on a Rust-capable host | REQUIRED / NOT YET RUN |
| Native benchmark on target old hardware | REQUIRED / NOT YET RUN |
| Persistent compute store | BLOCKED until tests pass |
| `sched_ext` canary | BLOCKED until user-space gates pass |
| DAMON-driven policy changes | BLOCKED; observation only first |
| GUI/compositor | LATER MILESTONE |

## Status

**Pre-alpha / architecture bootstrap. Do not use for production workloads.**

The repository is being built from a clean public-safe boundary so that no private DDC implementation details are required to participate in or review DDC-OS.
