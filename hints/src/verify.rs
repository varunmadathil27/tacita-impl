use ark_bls12_381::Bls12_381;
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::Field;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use std::ops::{Add, Mul};

use crate::types::{F, G1, G2, Proof, VerifierPreprocessing};

fn verify_opening(
    vp: &VerifierPreprocessing,
    commitment: &G1,
    point: &F,
    evaluation: &F,
    opening_proof: &G1,
) {
    let eval_com: G1 = vp.g_0.mul(evaluation).into();
    let point_com: G2 = vp.h_0.mul(point).into();

    let lhs = <Bls12_381 as Pairing>::pairing(*commitment - eval_com, vp.h_0);
    let rhs = <Bls12_381 as Pairing>::pairing(*opening_proof, vp.h_1 - point_com);
    assert_eq!(lhs, rhs);
}

fn verify_openings(vp: &VerifierPreprocessing, proof: &Proof) {
    let adjustment = F::from(0) - proof.agg_weight;
    let adjustment_com = vp.l_n_minus_1_of_x_com.mul(adjustment);
    let w_of_x_com: G1 = (vp.w_of_x_com + adjustment_com).into();

    let psw_of_r_argument = proof.psw_of_x_com - vp.g_0.mul(proof.psw_of_r).into_affine();
    let w_of_r_argument = w_of_x_com - vp.g_0.mul(proof.w_of_r).into_affine();
    let b_of_r_argument = proof.b_of_x_com - vp.g_0.mul(proof.b_of_r).into_affine();
    let psw_wff_q_of_r_argument =
        proof.psw_wff_q_of_x_com - vp.g_0.mul(proof.psw_wff_q_of_r).into_affine();
    let psw_check_q_of_r_argument =
        proof.psw_check_q_of_x_com - vp.g_0.mul(proof.psw_check_q_of_r).into_affine();
    let b_wff_q_of_r_argument =
        proof.b_wff_q_of_x_com - vp.g_0.mul(proof.b_wff_q_of_r).into_affine();
    let b_check_q_of_r_argument =
        proof.b_check_q_of_x_com - vp.g_0.mul(proof.b_check_q_of_r).into_affine();

    let merged_argument: G1 = (psw_of_r_argument
        + w_of_r_argument.mul(proof.r.pow([1]))
        + b_of_r_argument.mul(proof.r.pow([2]))
        + psw_wff_q_of_r_argument.mul(proof.r.pow([3]))
        + psw_check_q_of_r_argument.mul(proof.r.pow([4]))
        + b_wff_q_of_r_argument.mul(proof.r.pow([5]))
        + b_check_q_of_r_argument.mul(proof.r.pow([6])))
    .into_affine();

    let lhs = <Bls12_381 as Pairing>::pairing(merged_argument, vp.h_0);
    let rhs =
        <Bls12_381 as Pairing>::pairing(proof.merged_proof, vp.h_1 - vp.h_0.mul(proof.r).into_affine());
    assert_eq!(lhs, rhs);

    let domain = Radix2EvaluationDomain::<F>::new(vp.n).unwrap();
    let omega: F = domain.group_gen;
    let r_div_omega: F = proof.r / omega;
    verify_opening(
        vp,
        &proof.psw_of_x_com,
        &r_div_omega,
        &proof.psw_of_r_div_omega,
        &proof.psw_of_r_div_omega_proof,
    );
}

pub fn verify(vp: &VerifierPreprocessing, proof: &Proof) {
    let domain = Radix2EvaluationDomain::<F>::new(vp.n).unwrap();
    let omega: F = domain.group_gen;

    verify_openings(vp, proof);

    let n: u64 = vp.n as u64;
    let vanishing_of_r: F = proof.r.pow([n]) - F::from(1);
    let omega_pow_n_minus_1 = omega.pow([n - 1]);
    let l_n_minus_1_of_r =
        (omega_pow_n_minus_1 / F::from(n)) * (vanishing_of_r / (proof.r - omega_pow_n_minus_1));

    let lhs = <Bls12_381 as Pairing>::pairing(&proof.b_of_x_com, &vp.sk_of_x_com);
    let x1 =
        <Bls12_381 as Pairing>::pairing(&proof.aggregate_material.sk_q1_com, &vp.vanishing_com);
    let x2 =
        <Bls12_381 as Pairing>::pairing(&proof.aggregate_material.sk_q2_com, &vp.x_monomial_com);
    let x3 = <Bls12_381 as Pairing>::pairing(&proof.agg_pk, &vp.h_0);
    let rhs = x1.add(x2).add(x3);
    assert_eq!(lhs, rhs);

    let lhs = proof.psw_of_r - proof.psw_of_r_div_omega - proof.w_of_r * proof.b_of_r;
    let rhs = proof.psw_wff_q_of_r * vanishing_of_r;
    assert_eq!(lhs, rhs);

    let lhs = l_n_minus_1_of_r * proof.psw_of_r;
    let rhs = vanishing_of_r * proof.psw_check_q_of_r;
    assert_eq!(lhs, rhs);

    let lhs = proof.b_of_r * proof.b_of_r - proof.b_of_r;
    let rhs = proof.b_wff_q_of_r * vanishing_of_r;
    assert_eq!(lhs, rhs);

    let lhs = l_n_minus_1_of_r * (proof.b_of_r - F::from(1));
    let rhs = vanishing_of_r * proof.b_check_q_of_r;
    assert_eq!(lhs, rhs);
}
