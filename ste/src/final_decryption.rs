use ark_ec::pairing::{Pairing, PairingOutput};

use crate::{
    aggregate::AggregateKey,
    crs::CRS,
    decryption::agg_dec,
    encryption::Ciphertext,
    setup::PartialDecryption,
};

pub fn finalize_decryption<E: Pairing>(
    partial_decryptions: &[PartialDecryption<E>],
    aggregate_ciphertext: &Ciphertext<E>,
    selector: &[bool],
    aggregate_key: &AggregateKey<E>,
    crs: &CRS<E>,
) -> Vec<PairingOutput<E>> {
    agg_dec(
        &partial_decryptions.to_vec(),
        aggregate_ciphertext,
        selector,
        aggregate_key,
        crs,
    )
}
