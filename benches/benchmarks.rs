use aes::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn subword_benchmark(c: &mut Criterion) {
    c.bench_function("subword", |b| b.iter(|| SubWord(black_box(0))));
}

fn expand_128_bit_key_expansion(c: &mut Criterion) {
    c.bench_function("expand 128 bit key", |b|
        b.iter(||
            expand_128_bit_key(black_box([0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c]))
        )
    );
}

fn expand_196_bit_key_expansion(c: &mut Criterion) {
    c.bench_function("expand 196 bit key", |b|
        b.iter(||
            expand_196_bit_key(black_box([0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b]))
        )
    );
}


fn expand_256_bit_key_expansion(c: &mut Criterion) {
    c.bench_function("expand 256 bit key", |b|
        b.iter(||
            expand_256_bit_key(black_box([0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4]))
        )
    );
}

fn aes_128_benchmark(c: &mut Criterion) {
    c.bench_function("AES-128", |b|
        b.iter(|| {
            let mut input: [u32; 4] = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];
            let key: [u32; 4] = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f];

            aes_128(black_box(&mut input), black_box(key));
        })
    );
}

fn aes_196_benchmark(c: &mut Criterion) {
    c.bench_function("AES-196", |b|
        b.iter(|| {
            let mut input: [u32; 4] = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];
            let key: [u32; 6] =       [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617];

            aes_196(black_box(&mut input), black_box(key));
        })
    );
}

fn aes_256_benchmark(c: &mut Criterion) {
    c.bench_function("AES-256", |b|
        b.iter(|| {
            let mut input: [u32; 4] = [0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff];
            let key: [u32; 8] = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f];

            aes_256(black_box(&mut input), black_box(key));
        })
    );
}

criterion_group!(benches, subword_benchmark, expand_128_bit_key_expansion, expand_196_bit_key_expansion, expand_256_bit_key_expansion, aes_128_benchmark, aes_196_benchmark, aes_256_benchmark);
criterion_main!(benches);
