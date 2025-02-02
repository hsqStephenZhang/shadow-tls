use blake2::digest::FixedOutput;
use criterion::{criterion_group, criterion_main, Criterion};
use hmac::{Hmac, Mac};
use sha1::Sha1;

const KEY: &[u8] = b"supersecretkey";
const SMALL_DATA: &[u8] = b"Hello, World!";
const LARGE_DATA: &[u8] = include_bytes!("../docs/protocol-v3-en.md");

fn hmac_sha1_benchmark1(c: &mut Criterion) {
    c.bench_function("HMAC-SHA1-SMALL", |b| {
        b.iter(|| {
            let mut mac = Hmac::<Sha1>::new_from_slice(KEY).expect("HMAC can take key of any size");
            mac.update(SMALL_DATA);
            let _result = mac.finalize();
        })
    });
}

fn hmac_sha1_benchmark2(c: &mut Criterion) {
    c.bench_function("HMAC-SHA1-LARGE", |b| {
        b.iter(|| {
            let mut mac = Hmac::<Sha1>::new_from_slice(KEY).expect("HMAC can take key of any size");
            mac.update(LARGE_DATA);
            let _result = mac.finalize();
        })
    });
}

fn mac_blake2b_benchmark1(c: &mut Criterion) {
    c.bench_function("MAC-BLAKE2b-SMALL", |b| {
        b.iter(|| {
            let mut mac = blake2::Blake2bMac::new_from_slice(KEY).unwrap();
            blake2::digest::Update::update(&mut mac, SMALL_DATA);
            let _: [u8; 4] = mac.finalize_fixed().into();
        })
    });
}

fn mac_blake2b_benchmark2(c: &mut Criterion) {
    c.bench_function("MAC-BLAKE2b-LARGE", |b| {
        b.iter(|| {
            let mut mac = blake2::Blake2bMac::new_from_slice(KEY).unwrap();
            blake2::digest::Update::update(&mut mac, LARGE_DATA);
            let _: [u8; 4] = mac.finalize_fixed().into();
        })
    });
}

fn mac_blake2s_benchmark1(c: &mut Criterion) {
    c.bench_function("MAC-BLAKE2s-SMALL", |b| {
        b.iter(|| {
            let mut mac = blake2::Blake2sMac::new_from_slice(KEY).unwrap();
            blake2::digest::Update::update(&mut mac, SMALL_DATA);
            let _: [u8; 4] = mac.finalize_fixed().into();
        })
    });
}

fn mac_blake2s_benchmark2(c: &mut Criterion) {
    c.bench_function("MAC-BLAKE2s-LARGE", |b| {
        b.iter(|| {
            let mut mac = blake2::Blake2sMac::new_from_slice(KEY).unwrap();
            blake2::digest::Update::update(&mut mac, LARGE_DATA);
            let _: [u8; 4] = mac.finalize_fixed().into();
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

fn hmac_blake2s_simd_benchmark2(c: &mut Criterion) {
    c.bench_function("HMAC-BLAKE2S-SIMD-LARGE", |b| {
        b.iter(|| {
            let mut hmac = blake2s_simd::Params::new();
            hmac.key(KEY);
            let _res = hmac.hash(LARGE_DATA);
        })
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    hmac_sha1_benchmark1(c);
    hmac_sha1_benchmark2(c);
    mac_blake2b_benchmark1(c);
    mac_blake2b_benchmark2(c);
    mac_blake2s_benchmark1(c);
    mac_blake2s_benchmark2(c);
    hmac_blake2s_simple_benchmark1(c);
    hmac_blake2s_simple_benchmark2(c);
    hmac_blake2b_simple_benchmark1(c);
    hmac_blake2b_simple_benchmark2(c);
    hmac_blake2s_simd_benchmark2(c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
