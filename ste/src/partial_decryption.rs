use ark_ec::pairing::Pairing;

use crate::{
    encryption::Ciphertext,
    setup::SecretKey,
};

pub use crate::setup::PartialDecryption;

pub fn compute_partial_decryption<E: Pairing>(
    secret_key: &SecretKey<E>,
    ciphertext: &Ciphertext<E>,
) -> PartialDecryption<E> {
    secret_key.partial_decryption(ciphertext)
}

pub fn zero_partial_decryption<E: Pairing>() -> PartialDecryption<E> {
    PartialDecryption::zero()
}
