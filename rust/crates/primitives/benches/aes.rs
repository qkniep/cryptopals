use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use cryptopals_primitives::aes::{State, cipher, inv_cipher, key_expansion};

fn criterion_benchmark(c: &mut Criterion) {
    const PLAINTEXT: [u32; 4] = [0x3243f6a8, 0x885a308d, 0x313198a2, 0xe0370734];
    const KEY: [u32; 4] = [0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c];

    c.bench_function("AES key expansion", |b| {
        b.iter(|| {
            let keys = key_expansion(black_box(KEY));
            black_box(keys);
        })
    });

    let expanded_key = key_expansion(KEY);

    c.bench_function("AES cipher", |b| {
        b.iter(|| {
            let ciphertext = cipher(black_box(State(PLAINTEXT)), 10, black_box(expanded_key));
            black_box(ciphertext);
        })
    });

    c.bench_function("AES inv. cipher output", |b| {
        b.iter_batched(
            || cipher(State(PLAINTEXT), 10, expanded_key),
            |ciphertext| {
                let plaintext = inv_cipher(ciphertext, 10, black_box(expanded_key));
                black_box(plaintext);
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
