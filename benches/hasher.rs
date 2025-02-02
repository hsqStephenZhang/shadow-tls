use criterion::{criterion_group, criterion_main, Criterion};
use hmac::{Mac, SimpleHmac};
use sha1::Sha1;

const KEY: &[u8] = b"supersecretkey";
const SMALL_DATA: &[u8] = b"Hello, World!";
const LARGE_DATA: &[u8] = include_bytes!("../docs/protocol-v3-en.md");

fn hmac_sha1_benchmark1(c: &mut Criterion) {
    c.bench_function("HMAC-SHA1-SMALL", |b| {
        b.iter(|| {
            let mut mac =
                SimpleHmac::<Sha1>::new_from_slice(KEY).expect("HMAC can take key of any size");
            mac.update(SMALL_DATA);
            let _result = mac.finalize();
        })
    });
}

fn hmac_sha1_benchmark2(c: &mut Criterion) {
    c.bench_function("HMAC-SHA1-LARGE", |b| {
        b.iter(|| {
            let mut mac =
                SimpleHmac::<Sha1>::new_from_slice(KEY).expect("HMAC can take key of any size");
            mac.update(LARGE_DATA);
            let _result = mac.finalize();
        })
    });
}

fn hmac_blake2s_simple_benchmark1(c: &mut Criterion) {
    c.bench_function("HMAC-BLAKE2s-SIMPLE-SMALL", |b| {
        b.iter(|| {
            type HmacBlake2s = hmac::SimpleHmac<blake2::Blake2s256>;
            let mut hmac = HmacBlake2s::new_from_slice(KEY).unwrap();
            hmac.update(SMALL_DATA);
            let _res = hmac.finalize();
        })
    });
}

fn hmac_blake2s_simple_benchmark2(c: &mut Criterion) {
    c.bench_function("HMAC-BLAKE2s-SIMPLE-LARGE", |b| {
        b.iter(|| {
            type HmacBlake2s = hmac::SimpleHmac<blake2::Blake2s256>;
            let mut hmac = HmacBlake2s::new_from_slice(KEY).unwrap();
            hmac.update(LARGE_DATA);
            let _res = hmac.finalize();
        })
    });
}

fn hmac_blake2b_simple_benchmark1(c: &mut Criterion) {
    c.bench_function("HMAC-BLAKE2b-SIMPLE-SMALL", |b| {
        b.iter(|| {
            type HmacBlake2b = hmac::SimpleHmac<blake2::Blake2b512>;
            let mut hmac = HmacBlake2b::new_from_slice(KEY).unwrap();
            hmac.update(SMALL_DATA);
            let _res = hmac.finalize();
        })
    });
}

fn hmac_blake2b_simple_benchmark2(c: &mut Criterion) {
    c.bench_function("HMAC-BLAKE2b-SIMPLE-LARGE", |b| {
        b.iter(|| {
            type HmacBlake2b = hmac::SimpleHmac<blake2::Blake2b512>;
            let mut hmac = HmacBlake2b::new_from_slice(KEY).unwrap();
            hmac.update(LARGE_DATA);
            let _res = hmac.finalize();
        })
    });
}

fn hmac_blake3_benchmark1(c: &mut Criterion) {
    c.bench_function("HMAC-BLAKE3-SIMPLE-SMALL", |b| {
        b.iter(|| {
            type HmacBlake3 = hmac::SimpleHmac<blake3::Hasher>;
            let mut hmac = HmacBlake3::new_from_slice(KEY).unwrap();
            hmac.update(SMALL_DATA);
            let _res = hmac.finalize();
        })
    });
}

fn hmac_blake3_benchmark2(c: &mut Criterion) {
    c.bench_function("HMAC-BLAKE3-SIMPLE-LARGE", |b| {
        b.iter(|| {
            type HmacBlake3 = hmac::SimpleHmac<blake3::Hasher>;
            let mut hmac = HmacBlake3::new_from_slice(KEY).unwrap();
            hmac.update(LARGE_DATA);
            let _res = hmac.finalize();
        })
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    hmac_sha1_benchmark1(c);
    hmac_sha1_benchmark2(c);
    hmac_blake3_benchmark1(c);
    hmac_blake3_benchmark2(c);
    hmac_blake2s_simple_benchmark1(c);
    hmac_blake2s_simple_benchmark2(c);
    hmac_blake2b_simple_benchmark1(c);
    hmac_blake2b_simple_benchmark2(c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
