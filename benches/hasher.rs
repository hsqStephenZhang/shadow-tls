use blake2::{Blake2b512, Blake2s256};
use blake3::Hasher as Blake3;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hmac::{Mac, SimpleHmac};
use rand::prelude::*;
use sha1::Sha1;
use sha2::Sha256;

const KEY: &[u8] = b"supersecretkey";
const KIB: usize = 1024;

trait BenchName {
    fn name() -> &'static str;
}

macro_rules! impl_bench_name {
    ($name:ident) => {
        impl BenchName for $name {
            fn name() -> &'static str {
                stringify!($name)
            }
        }
    };
}

impl_bench_name!(Sha1);
impl_bench_name!(Sha256);
impl_bench_name!(Blake2s256);
impl_bench_name!(Blake2b512);
impl_bench_name!(Blake3);

fn hmac_benchmark_inner<
    D: hmac::digest::Digest + hmac::digest::core_api::BlockSizeUser + BenchName,
>(
    c: &mut Criterion,
    sizes: &[usize],
    post_fix: &str,
) {
    let throughputs = sizes.iter().map(|size| Throughput::Bytes(*size as u64));

    let hmac_type = D::name();
    let mut group = c.benchmark_group(hmac_type);
    group.sample_size(1000);
    for (size, throughput) in sizes.iter().zip(throughputs) {
        group.throughput(throughput);
        let id = BenchmarkId::new(format!("HMAC-{}-{}", hmac_type, post_fix), size);
        group.bench_with_input(id, size, |b, _| {
            b.iter_batched(
                || {
                    let mut input = vec![0u8; *size];
                    thread_rng().fill_bytes(&mut input);
                    input
                },
                |input| {
                    let mut mac = SimpleHmac::<D>::new_from_slice(KEY)
                        .expect("HMAC can take key of any size");
                    mac.update(&input);
                    let _result = mac.finalize();
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
}

#[allow(unused)]
fn hmac_benchmark_large_packets<
    D: hmac::digest::Digest + hmac::digest::core_api::BlockSizeUser + BenchName,
>(
    c: &mut Criterion,
) {
    let sizes = [1, 2, 4, 8, 16, 32, 64, 100]
        .into_iter()
        .map(|x| x * KIB)
        .collect::<Vec<_>>();
    hmac_benchmark_inner::<D>(c, &sizes, "LARGE");
}

fn hmac_benchmark_small_packets<
    D: hmac::digest::Digest + hmac::digest::core_api::BlockSizeUser + BenchName,
>(
    c: &mut Criterion,
) {
    let sizes = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512]
        .into_iter()
        .map(|x| x)
        .collect::<Vec<_>>();
    hmac_benchmark_inner::<D>(c, &sizes, "SMALL");
}

fn criterion_benchmark(c: &mut Criterion) {
    hmac_benchmark_large_packets::<Sha1>(c);
    hmac_benchmark_large_packets::<Sha256>(c);
    hmac_benchmark_large_packets::<Blake2s256>(c);
    hmac_benchmark_large_packets::<Blake2b512>(c);
    hmac_benchmark_large_packets::<Blake3>(c);

    hmac_benchmark_small_packets::<Sha1>(c);
    hmac_benchmark_small_packets::<Sha256>(c);
    hmac_benchmark_small_packets::<Blake2s256>(c);
    hmac_benchmark_small_packets::<Blake2b512>(c);
    hmac_benchmark_small_packets::<Blake3>(c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
