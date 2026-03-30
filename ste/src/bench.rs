#![allow(clippy::needless_range_loop)]

use crate::{
    aggregate::{AggregateKey, EncryptionKey},
    crs::CRS,
    decryption::agg_dec,
    encryption::{encrypt, Ciphertext},
    setup::{LagPolys, PartialDecryption, SecretKey},
};

use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::PrimeGroup;
use ark_serialize::CanonicalSerialize;

use std::time::Instant;

type E = ark_bls12_381::Bls12_381;
type F = ark_bls12_381::Fr;

// ---------- helpers ----------

fn ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1_000.0
}

fn ser_len<T: CanonicalSerialize>(x: &T) -> usize {
    let mut v = Vec::new();
    x.serialize_compressed(&mut v).unwrap();
    v.len()
}

fn fmt_bytes(b: usize) -> String {
    if b < 1024 {
        format!("{} B", b)
    } else {
        format!("{:.2} kB", b as f64 / 1024.0)
    }
}

// Benchmark driver. Tweak parameters here or call from main with your own.
pub fn run_bench(n: usize, l: usize, t: usize, num_ct: usize) {
    assert!(n.is_power_of_two(), "n must be a power of two (FFT domain)");
    assert!(t < n, "threshold t must be < n");
    println!("params: n = {n}, l = {l}, t = {t}, num_ct = {num_ct}");

    // ---------------------------
    // 0) CRS (+ optional Lag polys for validation/consistency with tests)
    // ---------------------------
    let mut rng = ark_std::test_rng();

    let t0 = Instant::now();
    let crs = CRS::<E>::new(n, l, &mut rng);
    let dt_crs = t0.elapsed();

    // Not strictly needed for the pipeline that follows, but used by your tests
    // and handy if you later flip to position-oblivious PK aggregation.
    let t1 = Instant::now();
    let _lag_polys = LagPolys::<F>::new(n);
    let dt_lag = t1.elapsed();

    println!(
        "setup:   crs={} ms, lag_polys={} ms",
        ms(dt_crs),
        ms(dt_lag)
    );

    // Sizes of base group elements (sanity)
    {
        let mut g1b = Vec::new();
        let mut g2b = Vec::new();
        let mut gtb = Vec::new();
        <E as Pairing>::G1::generator()
            .serialize_compressed(&mut g1b)
            .unwrap();
        <E as Pairing>::G2::generator()
            .serialize_compressed(&mut g2b)
            .unwrap();
        PairingOutput::<E>::generator()
            .serialize_compressed(&mut gtb)
            .unwrap();
        println!(
            "sizes:   |G1|={}, |G2|={}, |GT|={}",
            fmt_bytes(g1b.len()),
            fmt_bytes(g2b.len()),
            fmt_bytes(gtb.len())
        );
        println!("sizes:   |CRS|={}", fmt_bytes(ser_len(&crs)));
    }

    // ---------------------------
    // 1) Keygen for n parties (fixed-position Lag public keys as in your tests)
    // ---------------------------
    let t2 = Instant::now();
    let mut sks = Vec::with_capacity(n);
    let mut lag_pks = Vec::with_capacity(n);
    for i in 0..n {
        let sk = SecretKey::<E>::new(&mut rng, i);
        let lag_pk = sk.get_lagrange_pk(i, &crs);
        sks.push(sk);
        lag_pks.push(lag_pk);
    }
    let dt_keygen = t2.elapsed();
    println!("keygen:  {} ms ({} parties)", ms(dt_keygen), n);

    // Sample sizes for (position-oblivious) PublicKey and (position-fixed) LagPublicKey
    {
        let pk_size = fmt_bytes({
            let mut v = Vec::new();
            // Build a position-oblivious PK once just to report size
            let tmp = sks[0].get_pk(&crs);
            tmp.serialize_compressed(&mut v).unwrap();
            v.len()
        });
        let lag_pk_size = fmt_bytes({
            let mut v = Vec::new();
            lag_pks[0].serialize_compressed(&mut v).unwrap();
            v.len()
        });
        println!("sizes:   PublicKey≈{}, LagPublicKey≈{}", pk_size, lag_pk_size);
    }

    // ---------------------------
    // 2) Aggregate public keys → (AggregateKey, EncryptionKey)
    // ---------------------------
    let t3 = Instant::now();
    let (ak, ek): (AggregateKey<E>, EncryptionKey<E>) = AggregateKey::new(lag_pks.clone(), &crs);
    let dt_ak = t3.elapsed();
    println!("agg-keys:{} ms", ms(dt_ak));

    println!(
        "sizes:   AggregateKey={}, EncryptionKey={}",
        fmt_bytes(ser_len(&ak)),
        fmt_bytes(ser_len(&ek))
    );

    // ---------------------------
    // 3) Encrypt `num_ct` messages (each is an l-slot vector in GT)
    // ---------------------------
    // Use GT generator (your tests do this) — if you prefer plaintexts, you can swap later.
    let base_m = vec![PairingOutput::<E>::generator(); l];

    let t4 = Instant::now();
    let mut cts: Vec<Ciphertext<E>> = Vec::with_capacity(num_ct);
    for _ in 0..num_ct {
        let ct = encrypt::<E>(&ek, t, &crs, &base_m, &mut rng);
        cts.push(ct);
    }
    let dt_enc = t4.elapsed();
    println!(
        "encrypt: {} ms ({} ciphertexts, l = {})",
        ms(dt_enc),
        num_ct,
        l
    );
    println!("sizes:   Ciphertext={}", fmt_bytes(ser_len(&cts[0])));

    // ---------------------------
    // 4) Homomorphic aggregation of ciphertexts
    // ---------------------------
    let t5 = Instant::now();
    let agg_ct = cts
        .iter()
        .skip(1)
        .fold(cts[0].clone(), |acc, c| acc.add(c));
    let dt_ct_agg = t5.elapsed();
    println!(
        "ct-agg:  {} ms (added {} cts into one)",
        ms(dt_ct_agg),
        num_ct
    );
    println!(
        "sizes:   AggregatedCiphertext={}",
        fmt_bytes(ser_len(&agg_ct))
    );

    // ---------------------------
    // 5) Partial decryption (first t parties produce shares; others are zero)
    // ---------------------------
    let t6 = Instant::now();
    let mut partials = Vec::with_capacity(n);
    for i in 0..t {
        partials.push(sks[i].partial_decryption(&agg_ct));
    }
    for _ in t..n {
        partials.push(PartialDecryption::<E>::zero());
    }
    let dt_pd = t6.elapsed();
    println!("pdec:    {} ms ({} shares)", ms(dt_pd), t);

    // Precise cryptographic payload size of one PD (G1 element, compressed).
    // (Note: excludes the small `id` integer.)
    {
        use ark_serialize::CanonicalSerialize;
        let mut v = Vec::new();
        partials[0].pd.serialize_compressed(&mut v).unwrap();
        println!("sizes:   PartialDecryption.share(pd)={}", fmt_bytes(v.len()));
    }

    // ---------------------------
    // 6) Final decryption (aggregate & *compute proofs* & combine)
    //     - This calls your `agg_dec`, which builds KZG commitments/openings (q0, qx, qhatx, …)
    //       and reconstructs the encryption key before outputting the recovered message.
    // ---------------------------
    let mut selector = vec![false; n];
    for i in 0..t {
        selector[i] = true;
    }

    let t7 = Instant::now();
    let recovered = agg_dec(&partials, &agg_ct, &selector, &ak, &crs);
    let dt_final = t7.elapsed();
    println!("final:   {} ms", ms(dt_final));

    // Sanity: the result should equal num_ct * base_m in GT (additively)
    let expected: Vec<PairingOutput<E>> = (0..l)
        .map(|_| PairingOutput::<E>::generator() * F::from(num_ct as u64))
        .collect();
    assert_eq!(recovered, expected, "decryption mismatch after aggregation");
    println!("check:   recovered OK ✅");

    // ---------------------------
    // Summary
    // ---------------------------
    println!("\n--- timing summary (ms) ---");
    println!("crs:     {:>10.3}", ms(dt_crs));
    println!("lag:     {:>10.3}", ms(dt_lag));
    println!("keygen:  {:>10.3}", ms(dt_keygen));
    println!("agg-keys:{:>10.3}", ms(dt_ak));
    println!("encrypt: {:>10.3}", ms(dt_enc));
    println!("ct-agg:  {:>10.3}", ms(dt_ct_agg));
    println!("pdec:    {:>10.3}", ms(dt_pd));
    println!("final:   {:>10.3}", ms(dt_final));
}

pub fn run_default_bench() {
    let n = 1 << 4;     // domain size / parties (must be a power of two)
    let l = 8;          // slots per ciphertext
    let t = n / 2;      // threshold / committee size
    let num_ct = 16;    // how many ciphertexts to encrypt & homomorphically add
    run_bench(n, l, t, num_ct);
}
