use ark_bls12_381::Bls12_381;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Polynomial,
    Radix2EvaluationDomain,
};
use ark_std::rand::Rng;
use ark_std::{test_rng, UniformRand};
use std::ops::{Div, Mul, Sub};

use crate::aggregate::{add_all_g2, preprocess_q1_contributions};
use crate::kzg::UniversalParams;
use crate::types::{
    Cache, F, G1, G2, KZG, PartySetupMaterial, ProverPreprocessing, VerifierPreprocessing,
};
use crate::utils;

pub fn sample_weights(n: usize) -> Vec<F> {
    let mut rng = &mut test_rng();
    (0..n).map(|_| F::from(u64::rand(&mut rng))).collect()
}

pub fn sample_bitmap(n: usize, probability: f64) -> Vec<F> {
    let rng = &mut test_rng();
    let mut bitmap = Vec::with_capacity(n);
    for _ in 0..n {
        bitmap.push(F::from(rng.gen_bool(probability)));
    }
    bitmap
}

pub fn sample_secret_keys(num_parties: usize) -> Vec<F> {
    let mut rng = test_rng();
    (0..num_parties).map(|_| F::rand(&mut rng)).collect()
}

pub fn prepare_cache(n: usize) -> Cache {
    let mut lagrange_polynomials = Vec::with_capacity(n);
    for i in 0..n {
        lagrange_polynomials.push(utils::lagrange_poly(n, i));
    }
    Cache {
        lagrange_polynomials,
    }
}

pub fn compute_poly(v: &[F]) -> DensePolynomial<F> {
    let domain = Radix2EvaluationDomain::<F>::new(v.len()).unwrap();
    let eval_form = Evaluations::from_vec_and_domain(v.to_vec(), domain);
    eval_form.interpolate()
}

pub fn setup(
    n: usize,
    params: &UniversalParams<Bls12_381>,
    weights: &[F],
    sk: &[F],
) -> (VerifierPreprocessing, ProverPreprocessing) {
    let mut weights = weights.to_vec();
    let mut sk = sk.to_vec();

    sk.push(F::from(0));
    weights.push(F::from(0));

    let w_of_x = compute_poly(&weights);
    let w_of_x_com = KZG::commit_g1(params, &w_of_x).unwrap();

    let all_parties_setup = crossbeam::scope(|s| {
        let mut threads = Vec::new();
        for i in 0..n {
            let idx = i;
            let secret = sk[idx];
            threads.push(s.spawn(move |_| party_i_setup_material(params, n, idx, &secret)));
        }

        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    })
    .unwrap();

    let mut q1_contributions: Vec<Vec<G1>> = Vec::with_capacity(n);
    let mut q2_contributions: Vec<G1> = Vec::with_capacity(n);
    let mut pks: Vec<G1> = Vec::with_capacity(n);
    let mut com_sks: Vec<G2> = Vec::with_capacity(n);

    for material in &all_parties_setup {
        q1_contributions.push(material.q1_material.clone());
        q2_contributions.push(material.q2_com);
        pks.push(material.pk);
        com_sks.push(material.com_sk_l_i_2);
    }

    let z_of_x = utils::compute_vanishing_poly(n);
    let x_monomial = utils::compute_x_monomial();
    let l_n_minus_1_of_x = utils::lagrange_poly(n, n - 1);

    let vp = VerifierPreprocessing {
        n,
        g_0: params.powers_of_g[0],
        h_0: params.powers_of_h[0],
        h_1: params.powers_of_h[1],
        l_n_minus_1_of_x_com: KZG::commit_g1(params, &l_n_minus_1_of_x).unwrap(),
        w_of_x_com,
        sk_of_x_com: add_all_g2(params, &com_sks),
        vanishing_com: KZG::commit_g2(params, &z_of_x).unwrap(),
        x_monomial_com: KZG::commit_g2(params, &x_monomial).unwrap(),
    };

    let pp = ProverPreprocessing {
        n,
        pks,
        q1_coms: preprocess_q1_contributions(&q1_contributions),
        q2_coms: q2_contributions,
    };

    (vp, pp)
}

pub fn party_i_setup_material(
    params: &UniversalParams<Bls12_381>,
    n: usize,
    i: usize,
    sk_i: &F,
) -> PartySetupMaterial {
    let l_i_of_x = utils::lagrange_poly(n, i);
    let z_of_x = utils::compute_vanishing_poly(n);

    let mut q1_material = Vec::with_capacity(n);
    for j in 0..n {
        let num: DensePolynomial<F> = if i == j {
            l_i_of_x.clone().mul(&l_i_of_x).sub(&l_i_of_x)
        } else {
            let l_j_of_x = utils::lagrange_poly(n, j);
            l_j_of_x.mul(&l_i_of_x)
        };
        let f = num.div(&z_of_x);
        let sk_times_f = utils::poly_eval_mult_c(&f, sk_i);
        q1_material.push(KZG::commit_g1(params, &sk_times_f).expect("commitment failed"));
    }

    let x_monomial = utils::compute_x_monomial();
    let l_i_of_0 = l_i_of_x.evaluate(&F::from(0));
    let l_i_of_0_poly = utils::compute_constant_poly(&l_i_of_0);
    let num = l_i_of_x.sub(&l_i_of_0_poly);
    let f = num.div(&x_monomial);
    let sk_times_f = utils::poly_eval_mult_c(&f, sk_i);
    let q2_com = KZG::commit_g1(params, &sk_times_f).expect("commitment failed");

    let sk_as_poly = utils::compute_constant_poly(sk_i);
    let pk = KZG::commit_g1(params, &sk_as_poly).expect("commitment failed");

    let sk_times_l_i_of_x = utils::poly_eval_mult_c(&l_i_of_x, sk_i);
    let com_sk_l_i_2 = KZG::commit_g2(params, &sk_times_l_i_of_x).expect("commitment failed");
    let com_sk_l_i_1 = KZG::commit_g1(params, &sk_times_l_i_of_x).expect("commitment failed");

    PartySetupMaterial {
        pk,
        com_sk_l_i_1,
        com_sk_l_i_2,
        q1_material,
        q2_com,
    }
}
