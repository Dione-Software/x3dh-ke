use x3dh_ke::{x3dh_a, x3dh_b, IdentityKey, SignedPreKey, EphemeralKey, OneTimePreKey, Key, calc_ad};
use criterion::{Criterion, criterion_group, criterion_main};

fn perform_double_x3dh() {
    let ika = IdentityKey::default();
    let ikas = ika.strip();
    let ikb = IdentityKey::default();
    let ikbs = ikb.strip();
    let spkb = SignedPreKey::default();
    let spkbs = spkb.strip();
    let eka = EphemeralKey::default();
    let ekas = eka.strip();
    let opkb = OneTimePreKey::default();
    let opkbs = opkb.strip();
    let signature = ikb.sign(&spkbs.pk_to_bytes());
    let _cka = x3dh_a(&signature, &ika, &spkbs, &eka, &ikbs, &opkbs).unwrap();
    let _ckb = x3dh_b(&ikas, &spkb, &ekas, &ikb, &opkb);
}

fn criterion_benchmark_1(c: &mut Criterion) {
    c.bench_function("double x3dh", |b| b.iter(|| perform_double_x3dh()));
}

fn serialize_deserialize() {
    let ika = IdentityKey::default();
    let data = ika.to_bytes();
    let _ikr = IdentityKey::from_bytes(&data).unwrap();
}

fn criterion_benchmark_2(c: &mut Criterion) {
    c.bench_function("serialize deserialize", |b| b.iter(|| serialize_deserialize()));
}

fn calc_ad_bench() {
    let ika = IdentityKey::default();
    let ikb = IdentityKey::default();
    let _ad = calc_ad(&ika, &ikb);
}

fn criterion_benchmark_3(c: &mut Criterion) {
    c.bench_function("calculate ad", |b| b.iter(|| calc_ad_bench()));
}

criterion_group!(benches, criterion_benchmark_1, criterion_benchmark_2, criterion_benchmark_3);
criterion_main!(benches);