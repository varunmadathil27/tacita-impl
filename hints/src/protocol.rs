use std::time::{Duration, Instant};

use ark_ff::UniformRand;
use ark_std::test_rng;

use crate::aggregate::{build_aggregate_proof_material, zero_poly_com_g1, zero_poly_com_g2};
use crate::kzg::UniversalParams;
use crate::prove::{compute_proof_size, compute_signature_size, prove};
use crate::setup::{prepare_cache, sample_bitmap, sample_secret_keys, sample_weights, setup};
use crate::signer::sign;
use crate::types::{ClientSignature, F, KZG, SHint, SkSHint};
use crate::verify::verify;

pub fn empty_client_signature(params: &UniversalParams<ark_bls12_381::Bls12_381>) -> ClientSignature {
    ClientSignature {
        message_commitment: zero_poly_com_g1(params),
        signature: zero_poly_com_g2(params),
        shint: SHint {
            pk_times_message: zero_poly_com_g1(params),
            sk_l_i_commitment_times_message: zero_poly_com_g1(params),
            q1_sum_times_message: zero_poly_com_g1(params),
            q2_commitment_times_message: zero_poly_com_g1(params),
        },
        skshint: SkSHint {
            q1_commitment_times_message: zero_poly_com_g1(params),
            q2_commitment_times_message: zero_poly_com_g1(params),
        },
    }
}

pub fn run_demo() {
    let n = 1 << 10;
    println!("n = {}", n);

    let cache = prepare_cache(n);
    let rng = &mut test_rng();
    let params = KZG::setup(n, rng).expect("Setup failed");

    let sk = sample_secret_keys(n - 1);
    let weights = sample_weights(n - 1);

    let start = Instant::now();
    let (vp, pp) = setup(n, &params, &weights, &sk);
    let duration = start.elapsed();
    println!("Time taken for universe setup: {:?}", duration);

    println!("We start the signing process");

    let bitmap = sample_bitmap(n - 1, 0.9);
    let mut signatures = Vec::with_capacity(bitmap.len());
    let mut counter = 0;
    let mut total_duration = Duration::new(0, 0);

    for i in 0..bitmap.len() {
        if bitmap[i] == F::from(1) {
            counter += 1;
            let start = Instant::now();
            let message = F::rand(&mut test_rng());
            let signature = sign(&params, &pp, &sk[i], &vp.h_0, &message, i);
            total_duration += start.elapsed();
            signatures.push(signature);
        } else {
            signatures.push(empty_client_signature(&params));
        }
    }

    println!(
        "Average Time taken for signing when n = {} is: {:?}",
        n,
        total_duration / counter
    );
    println!("Signatures: {:?}", signatures.len());

    match compute_signature_size(&signatures[5]) {
        Ok(size) => println!("Size of the signature: {:.2} KB", size),
        Err(e) => println!("Failed to compute size of the signature: {:?}", e),
    }

    println!("Retrieved signatures");

    let start = Instant::now();
    let proof = prove(&params, &pp, &cache, &weights, &bitmap, &signatures);
    println!("Time elapsed in prover is: {:?}", start.elapsed());

    match compute_proof_size(&proof) {
        Ok(size) => println!("Size of the proof: {:.2} KB", size),
        Err(e) => println!("Failed to compute size of the proof: {:?}", e),
    }

    let aggregate_material =
        build_aggregate_proof_material(&params, &pp, &bitmap, &signatures).expect("consistent inputs");
    println!(
        "Aggregate proof material ready: s_q1={}, s_q2={}, sk_s_q1={}, sk_s_q2={}",
        aggregate_material.s_q1_com,
        aggregate_material.s_q2_com,
        aggregate_material.sk_s_q1_com,
        aggregate_material.sk_s_q2_com
    );

    let start = Instant::now();
    verify(&vp, &proof);
    println!("Time elapsed in verifier is: {:?}", start.elapsed());
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;
    use std::ops::{Add, Mul};

    use crate::aggregate::filter_and_add_g1;
    use crate::setup::party_i_setup_material;

    fn tiny_instance() -> (
        UniversalParams<ark_bls12_381::Bls12_381>,
        crate::types::VerifierPreprocessing,
        crate::types::ProverPreprocessing,
        crate::types::Cache,
        Vec<F>,
        Vec<F>,
    ) {
        let n = 4;
        let params = KZG::setup(n, &mut test_rng()).unwrap();
        let weights = sample_weights(n - 1);
        let sk = sample_secret_keys(n - 1);
        let cache = prepare_cache(n);
        let (vp, pp) = setup(n, &params, &weights, &sk);
        (params, vp, pp, cache, weights, sk)
    }

    #[test]
    fn signer_output_shape() {
        let (params, vp, pp, _cache, _weights, sk) = tiny_instance();
        let message = F::from(7);
        let signature = sign(&params, &pp, &sk[0], &vp.h_0, &message, 0);

        let setup_material = party_i_setup_material(&params, pp.n, 0, &sk[0]);
        assert_eq!(
            signature.shint.pk_times_message,
            setup_material.pk.mul(message).into_affine()
        );
        assert_eq!(
            signature.shint.sk_l_i_commitment_times_message,
            setup_material.com_sk_l_i_1.mul(message).into_affine()
        );

        let mut expected_q1_sum = zero_poly_com_g1(&params);
        for q1 in &setup_material.q1_material {
            expected_q1_sum = expected_q1_sum.add(q1.mul(message)).into_affine();
        }
        assert_eq!(signature.shint.q1_sum_times_message, expected_q1_sum);

        let mut expected_sk_q1 = zero_poly_com_g1(&params);
        for q1 in &pp.q1_coms {
            expected_sk_q1 = expected_sk_q1.add(q1.mul(message)).into_affine();
        }
        assert_eq!(
            signature.skshint.q1_commitment_times_message,
            expected_sk_q1
        );
    }

    #[test]
    fn hint_vector_lengths() {
        let (params, _vp, _pp, _cache, _weights, sk) = tiny_instance();
        let n = 4;
        let material = party_i_setup_material(&params, n, 0, &sk[0]);
        assert_eq!(material.q1_material.len(), n);
    }

    #[test]
    fn aggregate_proof_input_consistency() {
        let (params, vp, pp, _cache, _weights, sk) = tiny_instance();
        let bitmap = vec![F::from(1), F::from(0), F::from(1)];
        let signatures = vec![
            sign(&params, &pp, &sk[0], &vp.h_0, &F::from(3), 0),
            empty_client_signature(&params),
            sign(&params, &pp, &sk[2], &vp.h_0, &F::from(5), 2),
        ];

        let material = build_aggregate_proof_material(&params, &pp, &bitmap, &signatures).unwrap();

        let mut extended_bitmap = bitmap.clone();
        extended_bitmap.push(F::from(1));

        let mut s_q1 = signatures
            .iter()
            .map(|signature| signature.shint.q1_sum_times_message)
            .collect::<Vec<_>>();
        let mut s_q2 = signatures
            .iter()
            .map(|signature| signature.shint.q2_commitment_times_message)
            .collect::<Vec<_>>();
        s_q1.push(zero_poly_com_g1(&params));
        s_q2.push(zero_poly_com_g1(&params));

        assert_eq!(
            material.sk_q1_com,
            filter_and_add_g1(&params, &pp.q1_coms, &extended_bitmap)
        );
        assert_eq!(
            material.sk_q2_com,
            filter_and_add_g1(&params, &pp.q2_coms, &extended_bitmap)
        );
        assert_eq!(material.s_q1_com, filter_and_add_g1(&params, &s_q1, &extended_bitmap));
        assert_eq!(material.s_q2_com, filter_and_add_g1(&params, &s_q2, &extended_bitmap));
    }

    #[test]
    fn verify_path_tiny_toy_instance() {
        let (params, vp, pp, cache, weights, sk) = tiny_instance();
        let bitmap = vec![F::from(1), F::from(1), F::from(0)];
        let signatures = vec![
            sign(&params, &pp, &sk[0], &vp.h_0, &F::from(2), 0),
            sign(&params, &pp, &sk[1], &vp.h_0, &F::from(4), 1),
            empty_client_signature(&params),
        ];

        let proof = prove(&params, &pp, &cache, &weights, &bitmap, &signatures);
        verify(&vp, &proof);
    }
}
