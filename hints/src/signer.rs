use ark_ec::CurveGroup;
use std::ops::{Add, Mul};

use crate::aggregate::zero_poly_com_g1;
use crate::kzg::UniversalParams;
use crate::setup::party_i_setup_material;
use crate::types::{ClientSignature, F, G1, G2, ProverPreprocessing, SHint, SkSHint};

pub fn sign(
    params: &UniversalParams<ark_bls12_381::Bls12_381>,
    pp: &ProverPreprocessing,
    secret_key: &F,
    tag: &G2,
    message: &F,
    i: usize,
) -> ClientSignature {
    let message_commitment: G1 = params.powers_of_g[0].mul(message).into_affine();

    let g_2_m_i = params.powers_of_h[0].mul(message);
    let tag_g_2_m_i = tag.add(&g_2_m_i);
    let signature = tag_g_2_m_i.mul(secret_key).into_affine();

    let setup_material = party_i_setup_material(params, pp.n, i, secret_key);

    let mut q1_sum_times_message = zero_poly_com_g1(params);
    for q1 in &setup_material.q1_material {
        q1_sum_times_message = q1_sum_times_message.add(q1.mul(message)).into_affine();
    }

    let shint = SHint {
        pk_times_message: setup_material.pk.mul(message).into_affine(),
        sk_l_i_commitment_times_message: setup_material.com_sk_l_i_1.mul(message).into_affine(),
        q1_sum_times_message,
        q2_commitment_times_message: setup_material.q2_com.mul(message).into_affine(),
    };

    let mut q1_commitment_times_message = zero_poly_com_g1(params);
    for q1elem in &pp.q1_coms {
        q1_commitment_times_message = q1_commitment_times_message
            .add(q1elem.mul(message))
            .into_affine();
    }

    let mut q2_commitment_times_message = zero_poly_com_g1(params);
    for q2elem in &pp.q2_coms {
        q2_commitment_times_message = q2_commitment_times_message
            .add(q2elem.mul(message))
            .into_affine();
    }

    let skshint = SkSHint {
        q1_commitment_times_message,
        q2_commitment_times_message,
    };

    ClientSignature {
        message_commitment,
        signature,
        shint,
        skshint,
    }
}
