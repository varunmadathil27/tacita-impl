use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;

use crate::kzg::KZG10;

pub type KZG = KZG10::<Bls12_381, UniPoly381>;
pub type UniPoly381 = DensePolynomial<<Bls12_381 as Pairing>::ScalarField>;
pub type F = ark_bls12_381::Fr;
pub type G1 = <Bls12_381 as Pairing>::G1Affine;
pub type G2 = <Bls12_381 as Pairing>::G2Affine;

#[derive(Clone, Debug, PartialEq)]
pub struct PartySetupMaterial {
    pub pk: G1,
    pub com_sk_l_i_1: G1,
    pub com_sk_l_i_2: G2,
    pub q1_material: Vec<G1>,
    pub q2_com: G1,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SHint {
    pub pk_times_message: G1,
    pub sk_l_i_commitment_times_message: G1,
    pub q1_sum_times_message: G1,
    pub q2_commitment_times_message: G1,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SkSHint {
    pub q1_commitment_times_message: G1,
    pub q2_commitment_times_message: G1,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ClientSignature {
    pub message_commitment: G1,
    pub signature: G2,
    pub shint: SHint,
    pub skshint: SkSHint,
}

pub type Signature = ClientSignature;

#[derive(Clone, Debug, PartialEq)]
pub struct AggregateProofMaterial {
    pub sk_q1_com: G1,
    pub sk_q2_com: G1,
    pub s_q1_com: G1,
    pub s_q2_com: G1,
    pub sk_s_q1_com: G1,
    pub sk_s_q2_com: G1,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Proof {
    pub agg_pk: G1,
    pub agg_weight: F,
    pub r: F,
    pub merged_proof: G1,
    pub psw_of_r: F,
    pub psw_of_r_div_omega: F,
    pub psw_of_r_div_omega_proof: G1,
    pub w_of_r: F,
    pub b_of_r: F,
    pub psw_wff_q_of_r: F,
    pub psw_check_q_of_r: F,
    pub b_wff_q_of_r: F,
    pub b_check_q_of_r: F,
    pub psw_of_x_com: G1,
    pub b_of_x_com: G1,
    pub psw_wff_q_of_x_com: G1,
    pub psw_check_q_of_x_com: G1,
    pub b_wff_q_of_x_com: G1,
    pub b_check_q_of_x_com: G1,
    pub aggregate_material: AggregateProofMaterial,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProverPreprocessing {
    pub n: usize,
    pub pks: Vec<G1>,
    pub q1_coms: Vec<G1>,
    pub q2_coms: Vec<G1>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifierPreprocessing {
    pub n: usize,
    pub g_0: G1,
    pub h_0: G2,
    pub h_1: G2,
    pub l_n_minus_1_of_x_com: G1,
    pub w_of_x_com: G1,
    pub sk_of_x_com: G2,
    pub vanishing_com: G2,
    pub x_monomial_com: G2,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Cache {
    pub lagrange_polynomials: Vec<DensePolynomial<F>>,
}
