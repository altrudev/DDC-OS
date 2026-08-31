use ddc_core::estimate_shared_delta_work;
use std::hint::black_box;
use std::time::{Duration, Instant};

const CHANNEL_COUNTS: [usize; 5] = [1, 2, 4, 8, 16];
const REPEATS: usize = 5;

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

fn env_len(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&value| value > 0)
        .unwrap_or(default)
}

fn main() {
    let base_len = env_len("DDC_BENCH_BASE_WORDS", 2_000_000);
    let delta_len = env_len("DDC_BENCH_DELTA_WORDS", 4_096);

    println!("DDC-OS v0.1 shared-delta benchmark");
    println!("base_words={base_len} delta_words_per_channel={delta_len} repeats={REPEATS}");
    println!("channels,baseline_ms,ddc_ms,time_speedup,work_leverage,verified");

    let base = sequence(base_len, 0xDDC0_0001);

    for channels in CHANNEL_COUNTS {
        let deltas: Vec<Vec<u64>> = (0..channels)
            .map(|index| sequence(delta_len, 0xA11C_E000u64.wrapping_add(index as u64)))
            .collect();

        // Warm both paths before timing.
        let warm_baseline = baseline(&base, &deltas);
        let warm_ddc = shared_delta(&base, &deltas);
        assert_eq!(warm_baseline, warm_ddc, "warm-up semantic mismatch");

        let (baseline_time, baseline_result) = best_of(|| baseline(&base, &deltas));
        let (ddc_time, ddc_result) = best_of(|| shared_delta(&base, &deltas));
        let verified = baseline_result == ddc_result;
        assert!(verified, "DDC result differs from baseline");

        let estimate = estimate_shared_delta_work(channels as u64, base_len as u64, delta_len as u64);
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
