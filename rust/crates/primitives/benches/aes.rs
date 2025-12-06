use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use cryptopals_primitives::aes::Aes128;

fn criterion_benchmark(c: &mut Criterion) {
    const PLAINTEXT: [u8; 16] = [
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07,
        0x34,
    ];
    const KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    c.bench_function("AES new", |b| {
        b.iter(|| {
            let aes = Aes128::new(black_box(KEY).as_slice());
            black_box(aes);
        })
    });

    let mut aes = Aes128::new(KEY.as_slice());

    c.bench_function("AES encrypt", |b| {
        b.iter(|| {
            let ciphertext = aes.encrypt_block(black_box(PLAINTEXT));
            black_box(ciphertext);
        })
    });

    c.bench_function("AES decrypt", |b| {
        b.iter_batched(
            || {
                let mut aes = Aes128::new(KEY.as_slice());
                aes.encrypt_block(black_box(PLAINTEXT))
            },
            |ciphertext| {
                let plaintext = aes.decrypt_block(ciphertext);
                black_box(plaintext);
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
