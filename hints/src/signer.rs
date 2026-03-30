use crate::kzg::*;
use crate::protocol::{get_zero_poly_com_g1, party_i_setup_material, ProverPreprocessing};
use ark_bls12_381::{Bls12_381};
use ark_ff::Zero;
use ark_poly::univariate::DensePolynomial;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::Field;
use std::ops::Mul;
use std::ops::Add;
type F = ark_bls12_381::Fr;
type G1 = <Bls12_381 as Pairing>::G1Affine;
type G2 = <Bls12_381 as Pairing>::G2Affine;

/// Struct representing a signature.
pub struct Signature {
    pub M_i: G1,              // Group element in G1
    pub sig_i: G2,            // Group element in G2
    pub shint_i: Vec<G1>,     // Vector of group elements in G1
    pub skshint_i: Vec<G1>,   // Vector of group elements in G1
}

/// Signs a message using the ProverPreprocessing (`pp`), secret key, and tag.
///
/// # Inputs:
/// - `params`: The universal parameters from KZG.
/// - `pp`: The `ProverPreprocessing` structure containing public keys and preprocessed data.
/// - `secret_key`: The secret key of the signer.
/// - `tag`: A group element in G2.
/// - `message`: The message to be signed (a field element).
///
/// # Output:
/// - A `Signature` struct containing the signature components.
pub fn sign(
    params: &UniversalParams<Bls12_381>,
    pp: &ProverPreprocessing,
    secret_key: &F,
    tag: &G2,
    message: &F,
    i: usize,
) -> Signature {
    // Step 1: Compute M_i = g_1^m_i
    let M_i: G1 = params.powers_of_g[0].mul(message).into_affine();

    // Step 2: Compute sig_i as (tag * g_2^m_i)^{secret_key}
    let g_2_m_i = params.powers_of_h[0].mul(message); // g_2^m_i
    let tag_g_2_m_i = tag.add(&g_2_m_i);              // tag * g_2^m_i
    let sig_i = tag_g_2_m_i.mul(secret_key).into_affine(); // (tag * g_2^m_i)^{secret_key}

    // Step 3: Compute shint_i for party `i`
    let (pk, com_sk_l_i_1, com_sk_l_i_2, q1_material, q2_com) = party_i_setup_material(params, pp.n, i, message);

    // Sum the elements of q1_material
    let mut q1_sum = get_zero_poly_com_g1(params); // Initialize the sum of q1_material
    for q1 in q1_material.iter() {
        q1_sum = q1_sum.add(q1).into_affine();
    }



    // Initialize shint_i and append each element from the output of party_i_setup_material
    let mut shint_i = vec![];
    shint_i.push(pk.mul(message).into_affine());
    shint_i.push(com_sk_l_i_1.mul(message).into_affine());
    shint_i.push(q1_sum);
    shint_i.push(q2_com.mul(message).into_affine());



    // Multiply each element of q1_contributions and q2_contributions by the message and append to shint_i
    

    let mut skshint_i = vec![];
    let mut q1 = get_zero_poly_com_g1(params); 
    for q1elem in pp.q1_coms.iter(){
        let _ = q1.add(q1elem.mul(message)).into_affine();

    }
    skshint_i.push(q1);
    
    
    let mut q2 = get_zero_poly_com_g1(params); 
    for q2elem in pp.q2_coms.iter(){
        let _ = q2.add(q2elem.mul(message)).into_affine();

    }
    skshint_i.push(q2);

    // println!("Length of shint_i: {}", shint_i.len());
    // println!("Length of skshint_i: {}", skshint_i.len());
    // Step 5: Return the signature as a struct
    Signature {
        M_i,
        sig_i,
        shint_i,
        skshint_i,
    }
}


// #[cfg(test)]
// mod tests {
//     use super::*;
//     use ark_std::test_rng;
//     use ark_ff::UniformRand;

//     #[test]
//     fn test_sign_function() {
//         // Initialize test parameters
//         let rng = &mut test_rng();
//         let params = UniversalParams::<Bls12_381>::setup(64, rng).expect("KZG setup failed");
//         let secret_key = F::rand(rng);
//         let message = F::rand(rng);
//         let tag = params.powers_of_h[0]; // Example tag (G2 generator)
//         let i = 0; // Test for party 0

//         // Create a mock ProverPreprocessing structure
//         let pp = ProverPreprocessing {
//             n: 64,
//             pks: vec![params.powers_of_g[0]; 64], // Mock public keys
//             q1_coms: vec![params.powers_of_g[0]; 64], // Mock q1 contributions
//             q2_coms: vec![params.powers_of_g[0]; 64], // Mock q2 contributions
//         };

//         // Call the sign function
//         let signature = sign(&params, &pp, &secret_key, &tag, &message, i);

//         // Assertions to verify the output
//         assert!(!signature.M_i.is_zero(), "M_i should not be zero");
//         assert!(!signature.sig_i.is_zero(), "sig_i should not be zero");
//     }
// }
