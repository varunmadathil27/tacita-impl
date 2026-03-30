use ark_bls12_381::Bls12_381;
use ark_ec::{pairing::Pairing, CurveGroup, VariableBaseMSM};
use ark_poly::Polynomial;
use std::ops::Add;

use crate::kzg::UniversalParams;
use crate::types::{
    AggregateProofMaterial, Cache, ClientSignature, F, G1, G2, KZG, ProverPreprocessing,
};
use crate::utils;

pub fn compute_apk(pp: &ProverPreprocessing, bitmap: &[F], cache: &Cache) -> G1 {
    let n = bitmap.len();
    let mut exponents = Vec::with_capacity(n);
    for i in 0..n {
        let l_i_of_x = cache.lagrange_polynomials[i].clone();
        let l_i_of_0 = l_i_of_x.evaluate(&F::from(0));
        let active = bitmap[i] == F::from(1);
        exponents.push(if active { l_i_of_0 } else { F::from(0) });
    }

    <<Bls12_381 as Pairing>::G1 as VariableBaseMSM>::msm(&pp.pks[..], &exponents)
        .unwrap()
        .into_affine()
}

pub fn preprocess_q1_contributions(q1_contributions: &[Vec<G1>]) -> Vec<G1> {
    let n = q1_contributions.len();
    let mut q1_coms = Vec::with_capacity(n);

    for i in 0..n {
        let mut party_i_q1_com = q1_contributions[i][i];
        for (j, row) in q1_contributions.iter().enumerate() {
            if i != j {
                party_i_q1_com = party_i_q1_com.add(row[i]).into();
            }
        }
        q1_coms.push(party_i_q1_com);
    }

    q1_coms
}

pub fn zero_poly_com_g1(params: &UniversalParams<Bls12_381>) -> G1 {
    let zero_poly = utils::compute_constant_poly(&F::from(0));
    KZG::commit_g1(params, &zero_poly).unwrap()
}

pub fn zero_poly_com_g2(params: &UniversalParams<Bls12_381>) -> G2 {
    let zero_poly = utils::compute_constant_poly(&F::from(0));
    KZG::commit_g2(params, &zero_poly).unwrap()
}

pub fn filter_and_add_g1(
    params: &UniversalParams<Bls12_381>,
    elements: &[G1],
    bitmap: &[F],
) -> G1 {
    let mut com = zero_poly_com_g1(params);
    for i in 0..bitmap.len() {
        if bitmap[i] == F::from(1) {
            com = com.add(elements[i]).into_affine();
        }
    }
    com
}

pub fn add_all_g2(params: &UniversalParams<Bls12_381>, elements: &[G2]) -> G2 {
    let mut com = zero_poly_com_g2(params);
    for element in elements {
        com = com.add(*element).into_affine();
    }
    com
}

pub fn build_aggregate_proof_material(
    params: &UniversalParams<Bls12_381>,
    pp: &ProverPreprocessing,
    bitmap: &[F],
    signatures: &[ClientSignature],
) -> Result<AggregateProofMaterial, &'static str> {
    if signatures.len() + 1 != pp.n {
        return Err("expected signatures for exactly n-1 client slots");
    }
    if bitmap.len() + 1 != pp.n {
        return Err("expected bitmap for exactly n-1 client slots");
    }

    let mut extended_bitmap = bitmap.to_vec();
    extended_bitmap.push(F::from(1));

    let mut s_q1_sums = signatures
        .iter()
        .map(|signature| signature.shint.q1_sum_times_message)
        .collect::<Vec<_>>();
    let mut s_q2_sums = signatures
        .iter()
        .map(|signature| signature.shint.q2_commitment_times_message)
        .collect::<Vec<_>>();
    let mut sks_q1_sums = signatures
        .iter()
        .map(|signature| signature.skshint.q1_commitment_times_message)
        .collect::<Vec<_>>();
    let mut sks_q2_sums = signatures
        .iter()
        .map(|signature| signature.skshint.q2_commitment_times_message)
        .collect::<Vec<_>>();

    s_q1_sums.push(zero_poly_com_g1(params));
    s_q2_sums.push(zero_poly_com_g1(params));
    sks_q1_sums.push(zero_poly_com_g1(params));
    sks_q2_sums.push(zero_poly_com_g1(params));

    Ok(AggregateProofMaterial {
        sk_q1_com: filter_and_add_g1(params, &pp.q1_coms, &extended_bitmap),
        sk_q2_com: filter_and_add_g1(params, &pp.q2_coms, &extended_bitmap),
        s_q1_com: filter_and_add_g1(params, &s_q1_sums, &extended_bitmap),
        s_q2_com: filter_and_add_g1(params, &s_q2_sums, &extended_bitmap),
        sk_s_q1_com: filter_and_add_g1(params, &sks_q1_sums, &extended_bitmap),
        sk_s_q2_com: filter_and_add_g1(params, &sks_q2_sums, &extended_bitmap),
    })
}
