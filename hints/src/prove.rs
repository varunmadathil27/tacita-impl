use ark_bls12_381::Bls12_381;
use ark_ff::Field;
use ark_poly::{EvaluationDomain, Polynomial, Radix2EvaluationDomain};
use ark_serialize::{CanonicalSerialize, SerializationError};
use ark_std::{ops::*, test_rng, UniformRand};

use crate::aggregate::{build_aggregate_proof_material, compute_apk};
use crate::kzg::UniversalParams;
use crate::setup::compute_poly;
use crate::types::{Cache, ClientSignature, F, G1, KZG, Proof, ProverPreprocessing};
use crate::utils;

pub fn compute_psw_poly(weights: &[F], bitmap: &[F]) -> ark_poly::univariate::DensePolynomial<F> {
    let n = weights.len();
    let mut parsum = F::from(0);
    let mut evals = Vec::with_capacity(n);
    for i in 0..n {
        parsum += bitmap[i] * weights[i];
        evals.push(parsum);
    }

    let domain = Radix2EvaluationDomain::<F>::new(n).unwrap();
    let eval_form = ark_poly::Evaluations::from_vec_and_domain(evals, domain);
    eval_form.interpolate()
}

pub fn prove(
    params: &UniversalParams<Bls12_381>,
    pp: &ProverPreprocessing,
    cache: &Cache,
    weights: &[F],
    bitmap: &[F],
    signatures: &[ClientSignature],
) -> Proof {
    let n = pp.n;

    let mut weights = weights.to_vec();
    let total_active_weight = bitmap
        .iter()
        .zip(weights.iter())
        .fold(F::from(0), |acc, (&x, &y)| acc + (x * y));
    weights.push(F::from(0) - total_active_weight);

    let mut extended_bitmap = bitmap.to_vec();
    extended_bitmap.push(F::from(1));

    let mut rng = test_rng();
    let r = F::rand(&mut rng);

    let domain = Radix2EvaluationDomain::<F>::new(n).unwrap();
    let omega: F = domain.group_gen;
    let r_div_omega: F = r / omega;
    let omega_inv: F = F::from(1) / omega;

    let z_of_x = utils::compute_vanishing_poly(n);
    let l_n_minus_1_of_x = utils::lagrange_poly(n, n - 1);
    let w_of_x = compute_poly(&weights);
    let b_of_x = compute_poly(&extended_bitmap);
    let psw_of_x = compute_psw_poly(&weights, &extended_bitmap);
    let psw_of_x_div_omega = utils::poly_domain_mult_ω(&psw_of_x, &omega_inv);

    let t_of_x = psw_of_x.sub(&psw_of_x_div_omega).sub(&w_of_x.mul(&b_of_x));
    let psw_wff_q_of_x = t_of_x.div(&z_of_x);

    let t_of_x = l_n_minus_1_of_x.mul(&psw_of_x);
    let psw_check_q_of_x = t_of_x.div(&z_of_x);

    let t_of_x = b_of_x.mul(&b_of_x).sub(&b_of_x);
    let b_wff_q_of_x = t_of_x.div(&z_of_x);

    let t_of_x = l_n_minus_1_of_x
        .clone()
        .mul(&b_of_x.clone().sub(&utils::compute_constant_poly(&F::from(1))));
    let b_check_q_of_x = t_of_x.div(&z_of_x);

    let aggregate_material =
        build_aggregate_proof_material(params, pp, bitmap, signatures).expect("invalid proof inputs");

    let agg_pk = compute_apk(pp, &extended_bitmap, cache);

    let psw_of_r_proof = KZG::compute_opening_proof(params, &psw_of_x, &r).unwrap();
    let w_of_r_proof = KZG::compute_opening_proof(params, &w_of_x, &r).unwrap();
    let b_of_r_proof = KZG::compute_opening_proof(params, &b_of_x, &r).unwrap();
    let psw_wff_q_of_r_proof = KZG::compute_opening_proof(params, &psw_wff_q_of_x, &r).unwrap();
    let psw_check_q_of_r_proof = KZG::compute_opening_proof(params, &psw_check_q_of_x, &r).unwrap();
    let b_wff_q_of_r_proof = KZG::compute_opening_proof(params, &b_wff_q_of_x, &r).unwrap();
    let b_check_q_of_r_proof = KZG::compute_opening_proof(params, &b_check_q_of_x, &r).unwrap();

    let merged_proof: G1 = (psw_of_r_proof
        + w_of_r_proof.mul(r.pow([1]))
        + b_of_r_proof.mul(r.pow([2]))
        + psw_wff_q_of_r_proof.mul(r.pow([3]))
        + psw_check_q_of_r_proof.mul(r.pow([4]))
        + b_wff_q_of_r_proof.mul(r.pow([5]))
        + b_check_q_of_r_proof.mul(r.pow([6])))
    .into();

    Proof {
        agg_pk,
        agg_weight: total_active_weight,
        r,
        merged_proof,
        psw_of_r_div_omega: psw_of_x.evaluate(&r_div_omega),
        psw_of_r_div_omega_proof: KZG::compute_opening_proof(params, &psw_of_x, &r_div_omega)
            .unwrap(),
        psw_of_r: psw_of_x.evaluate(&r),
        w_of_r: w_of_x.evaluate(&r),
        b_of_r: b_of_x.evaluate(&r),
        psw_wff_q_of_r: psw_wff_q_of_x.evaluate(&r),
        psw_check_q_of_r: psw_check_q_of_x.evaluate(&r),
        b_wff_q_of_r: b_wff_q_of_x.evaluate(&r),
        b_check_q_of_r: b_check_q_of_x.evaluate(&r),
        psw_of_x_com: KZG::commit_g1(params, &psw_of_x).unwrap(),
        b_of_x_com: KZG::commit_g1(params, &b_of_x).unwrap(),
        psw_wff_q_of_x_com: KZG::commit_g1(params, &psw_wff_q_of_x).unwrap(),
        psw_check_q_of_x_com: KZG::commit_g1(params, &psw_check_q_of_x).unwrap(),
        b_wff_q_of_x_com: KZG::commit_g1(params, &b_wff_q_of_x).unwrap(),
        b_check_q_of_x_com: KZG::commit_g1(params, &b_check_q_of_x).unwrap(),
        aggregate_material,
    }
}

pub fn compute_signature_size(signature: &ClientSignature) -> Result<f64, SerializationError> {
    let mut serialized_signature = Vec::new();

    signature
        .message_commitment
        .serialize_compressed(&mut serialized_signature)?;
    signature
        .signature
        .serialize_compressed(&mut serialized_signature)?;
    signature
        .shint
        .pk_times_message
        .serialize_compressed(&mut serialized_signature)?;
    signature
        .shint
        .sk_l_i_commitment_times_message
        .serialize_compressed(&mut serialized_signature)?;
    signature
        .shint
        .q1_sum_times_message
        .serialize_compressed(&mut serialized_signature)?;
    signature
        .shint
        .q2_commitment_times_message
        .serialize_compressed(&mut serialized_signature)?;
    signature
        .skshint
        .q1_commitment_times_message
        .serialize_compressed(&mut serialized_signature)?;
    signature
        .skshint
        .q2_commitment_times_message
        .serialize_compressed(&mut serialized_signature)?;

    Ok(serialized_signature.len() as f64 / 1024.0)
}

pub fn compute_proof_size(proof: &Proof) -> Result<f64, SerializationError> {
    let mut serialized_proof = Vec::new();

    proof.agg_pk.serialize_compressed(&mut serialized_proof)?;
    proof.agg_weight.serialize_compressed(&mut serialized_proof)?;
    proof.r.serialize_compressed(&mut serialized_proof)?;
    proof.merged_proof.serialize_compressed(&mut serialized_proof)?;
    proof.psw_of_r.serialize_compressed(&mut serialized_proof)?;
    proof
        .psw_of_r_div_omega
        .serialize_compressed(&mut serialized_proof)?;
    proof
        .psw_of_r_div_omega_proof
        .serialize_compressed(&mut serialized_proof)?;
    proof.w_of_r.serialize_compressed(&mut serialized_proof)?;
    proof.b_of_r.serialize_compressed(&mut serialized_proof)?;
    proof.psw_wff_q_of_r.serialize_compressed(&mut serialized_proof)?;
    proof
        .psw_check_q_of_r
        .serialize_compressed(&mut serialized_proof)?;
    proof.b_wff_q_of_r.serialize_compressed(&mut serialized_proof)?;
    proof.b_check_q_of_r.serialize_compressed(&mut serialized_proof)?;
    proof.psw_of_x_com.serialize_compressed(&mut serialized_proof)?;
    proof.b_of_x_com.serialize_compressed(&mut serialized_proof)?;
    proof
        .psw_wff_q_of_x_com
        .serialize_compressed(&mut serialized_proof)?;
    proof
        .psw_check_q_of_x_com
        .serialize_compressed(&mut serialized_proof)?;
    proof
        .b_wff_q_of_x_com
        .serialize_compressed(&mut serialized_proof)?;
    proof
        .b_check_q_of_x_com
        .serialize_compressed(&mut serialized_proof)?;
    proof
        .aggregate_material
        .sk_q1_com
        .serialize_compressed(&mut serialized_proof)?;
    proof
        .aggregate_material
        .sk_q2_com
        .serialize_compressed(&mut serialized_proof)?;
    proof
        .aggregate_material
        .s_q1_com
        .serialize_compressed(&mut serialized_proof)?;
    proof
        .aggregate_material
        .s_q2_com
        .serialize_compressed(&mut serialized_proof)?;
    proof
        .aggregate_material
        .sk_s_q1_com
        .serialize_compressed(&mut serialized_proof)?;
    proof
        .aggregate_material
        .sk_s_q2_com
        .serialize_compressed(&mut serialized_proof)?;

    Ok(serialized_proof.len() as f64 / 1024.0)
}
