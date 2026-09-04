use ddc_core::estimate_shared_delta_work;
use std::hint::black_box;
use std::time::{Duration, Instant};

const CHANNEL_COUNTS: [usize; 7] = [1, 2, 4, 8, 16, 32, 64];
const REPEATS: usize = 5;
const DEFAULT_BASE_WORDS: usize = 2_000_000;
const DEFAULT_DELTA_WORDS: usize = 4_096;
const MAX_BASE_WORDS: usize = 16_000_000;
const MAX_DELTA_WORDS: usize = 262_144;

#[inline(never)]
fn sum_words(words: &[u64]) -> u128 {
    words
        .iter()
        .fold(0u128, |acc, &word| acc.wrapping_add(word as u128))
}

fn sequence(len: usize, seed: u64) -> Vec<u64> {
    let mut state = seed.max(1);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        // Deterministic xorshift64 sequence: reproducible and dependency-free.
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push(state);
    }
    out
}

fn baseline(base: &[u64], deltas: &[Vec<u64>]) -> Vec<u128> {
    deltas
        .iter()
        .map(|delta| {
            // black_box prevents the benchmark compiler from turning the
            // baseline into the optimized shared-base algorithm for us.
            sum_words(black_box(base)) + sum_words(black_box(delta.as_slice()))
        })
        .collect()
}

fn shared_delta(base: &[u64], deltas: &[Vec<u64>]) -> Vec<u128> {
    let shared = sum_words(black_box(base));
    deltas
        .iter()
        .map(|delta| shared + sum_words(black_box(delta.as_slice())))
        .collect()
}

fn best_of<F>(mut run: F) -> (Duration, Vec<u128>)
where
    F: FnMut() -> Vec<u128>,
{
    let mut best: Option<(Duration, Vec<u128>)> = None;
    for _ in 0..REPEATS {
        let start = Instant::now();
        let result = black_box(run());
        let elapsed = start.elapsed();
        match &best {
            None => best = Some((elapsed, result)),
            Some((duration, _)) if elapsed < *duration => best = Some((elapsed, result)),
            _ => {}
        }
    }
    best.expect("REPEATS is non-zero")
}

fn env_len(name: &str, default: usize, max: usize) -> usize {
    match std::env::var(name) {
        Ok(raw) => match raw.parse::<usize>() {
            Ok(value) if (1..=max).contains(&value) => value,
            _ => {
                eprintln!(
                    "ignoring unsafe {name}={raw:?}; allowed range is 1..={max}, using {default}"
                );
                default
            }
        },
        Err(_) => default,
    }
}

fn main() {
    let base_len = env_len("DDC_BENCH_BASE_WORDS", DEFAULT_BASE_WORDS, MAX_BASE_WORDS);
    let delta_len = env_len(
        "DDC_BENCH_DELTA_WORDS",
        DEFAULT_DELTA_WORDS,
        MAX_DELTA_WORDS,
    );

    println!("DDC-OS v0.3 workspace / v0.1 shared-delta workload");
    println!("base_words={base_len} delta_words_per_channel={delta_len} repeats={REPEATS}");
    println!("channels,baseline_ms,ddc_ms,time_speedup,work_leverage,verified");

    let base = sequence(base_len, 0xDDC0_0001);

    for channels in CHANNEL_COUNTS {
        let deltas: Vec<Vec<u64>> = (0..channels)
            .map(|index| sequence(delta_len, 0xA11C_E000u64.wrapping_add(index as u64)))
            .collect();

        // Warm both paths before timing and prove exact semantic equality.
        let warm_baseline = baseline(&base, &deltas);
        let warm_ddc = shared_delta(&base, &deltas);
        assert_eq!(warm_baseline, warm_ddc, "warm-up semantic mismatch");

        let (baseline_time, baseline_result) = best_of(|| baseline(&base, &deltas));
        let (ddc_time, ddc_result) = best_of(|| shared_delta(&base, &deltas));
        let verified = baseline_result == ddc_result;
        assert!(verified, "DDC result differs from baseline");

        let estimate =
            estimate_shared_delta_work(channels as u64, base_len as u64, delta_len as u64);
        let time_speedup = baseline_time.as_secs_f64() / ddc_time.as_secs_f64();

        println!(
            "{channels},{:.3},{:.3},{:.3},{:.3},{verified}",
            baseline_time.as_secs_f64() * 1000.0,
            ddc_time.as_secs_f64() * 1000.0,
            time_speedup,
            estimate.leverage_ratio(),
        );
    }
}
