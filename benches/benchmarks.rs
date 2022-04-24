use std::time::Duration;

use aes::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

fn subword_benchmark(c: &mut Criterion) {
    c.bench_function("subword", |b| b.iter(|| SubWord(black_box(0))));
}

fn key_expansion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Key Expansion");

    group.bench_function("128-bit", |b|
        b.iter(||
            expand_128_bit_key(black_box([0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c]))
        )
    );

    group.bench_function("196-bit", |b|
        b.iter(||
            expand_196_bit_key(black_box([0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b]))
        )
    );

    group.bench_function("256-bit", |b|
        b.iter(||
            expand_256_bit_key(black_box([0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4]))
        )
    );

    group.finish();
}

fn aes_encryption_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Encrytion");
    group.throughput(Throughput::Bytes(16));

    group.bench_function("AES-128", |b|
        b.iter(|| {
            let mut input: [u32; 4] = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];
            let key: [u32; 4] = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f];

            aes_128_encrypt(black_box(&mut input), black_box(key));
        })
    );

    group.bench_function("AES-196", |b|
        b.iter(|| {
            let mut input: [u32; 4] = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];
            let key: [u32; 6] =       [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617];

            aes_196_encrypt(black_box(&mut input), black_box(key));
        })
    );

    group.bench_function("AES-256", |b|
        b.iter(|| {
            let mut input: [u32; 4] = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];
            let key: [u32; 8] = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f];

            aes_256_encrypt(black_box(&mut input), black_box(key));
        })
    );

    group.finish();
}

fn aes_decryption_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Decryption");
    group.measurement_time(Duration::from_secs(30)).throughput(Throughput::Bytes(16));

    group.bench_function("AES-128", |b|
        b.iter(|| {
            let mut input: [u32; 4] = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];
            let key: [u32; 4] = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f];

            aes_128_decrypt(black_box(&mut input), black_box(key));
        })
    );

    group.bench_function("AES-196", |b|
        b.iter(|| {
            let mut input: [u32; 4] = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];
            let key: [u32; 6] = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617];

            aes_196_decrypt(black_box(&mut input), black_box(key));
        })
    );

    group.bench_function("AES-256", |b|
        b.iter(|| {
            let mut input: [u32; 4] = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];
            let key: [u32; 8] = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f];

            aes_256_decrypt(black_box(&mut input), black_box(key));
        })
    );

    group.finish();
}

criterion_group!{
    name = benches;
    config = Criterion::default().warm_up_time(Duration::from_secs(5)).sample_size(2500);
    targets = subword_benchmark, key_expansion_benchmark, aes_encryption_benchmark, aes_decryption_benchmark
}

criterion_main!(benches);
