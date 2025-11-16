use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_std::{UniformRand, Zero};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use silent_threshold_encryption::{
    decryption::agg_dec,
    encryption::encrypt,
    kzg::KZG10,
    setup::{AggregateKey, LagrangePowers, PublicKey, SecretKey},
};

type E = ark_bls12_381::Bls12_381;
type G2 = <E as Pairing>::G2;
type Fr = <E as Pairing>::ScalarField;
type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

fn bench_decrypt(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();
    let mut group = c.benchmark_group("decrypt");

    for size in 3..=10 {
        let n = 1 << size; // actually n-1 total parties. one party is a dummy party that is always true
        let t: usize = n / 2;

        let tau = Fr::rand(&mut rng);
        let params = KZG10::<E, UniPoly381>::setup(n, tau).unwrap();
        let lagrange_params = LagrangePowers::<E>::new(tau, n).unwrap();

        let mut sk: Vec<SecretKey<E>> = Vec::new();
        let mut pk: Vec<PublicKey<E>> = Vec::new();

        // create the dummy party's keys
        sk.push(SecretKey::<E>::new(&mut rng));
        sk[0].nullify();
        pk.push(sk[0].lagrange_get_pk(0, &lagrange_params, n).unwrap());

        for i in 1..n {
            sk.push(SecretKey::<E>::new(&mut rng));
            pk.push(sk[i].lagrange_get_pk(i, &lagrange_params, n).unwrap());
        }

        let agg_key = AggregateKey::<E>::new(pk, &params).unwrap();
        let ct = encrypt::<E, _>(&agg_key, t, &params, &mut rng).unwrap();

        // compute partial decryptions
        let mut partial_decryptions: Vec<G2> = Vec::new();
        for sk_i in sk.iter().take(t + 1) {
            partial_decryptions.push(sk_i.partial_decryption(&ct));
        }
        for _ in t + 1..n {
            partial_decryptions.push(G2::zero());
        }

        // compute the decryption key
        let mut selector: Vec<bool> = Vec::new();
        selector.extend(std::iter::repeat_n(true, t + 1));
        selector.extend(std::iter::repeat_n(false, n - t - 1));

        group.bench_with_input(
            BenchmarkId::from_parameter(n),
            &(partial_decryptions, ct, selector, agg_key, params),
            |b, inp| {
                b.iter(|| agg_dec(&inp.0, &inp.1, &inp.2, &inp.3, &inp.4));
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_decrypt);
criterion_main!(benches);
