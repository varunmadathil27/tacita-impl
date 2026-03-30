use ark_ec::pairing::Pairing;

use crate::{
    crs::CRS,
    encryption::Ciphertext,
    setup::{LagPolys, LagPublicKey, PublicKey},
};

pub use crate::aggregate::{
    AggregateKey, AggregateKey as AggregateKeyMaterial, EncryptionKey,
    EncryptionKey as EncryptionKeyMaterial, SystemPublicKeys,
};

pub fn aggregate_key_material<E: Pairing>(
    lag_public_keys: Vec<LagPublicKey<E>>,
    crs: &CRS<E>,
) -> (AggregateKey<E>, EncryptionKey<E>) {
    AggregateKey::new(lag_public_keys, crs)
}

pub fn build_system_public_keys<E: Pairing>(
    public_keys: Vec<PublicKey<E>>,
    crs: &CRS<E>,
    lag_polys: &LagPolys<E::ScalarField>,
    positions_per_party: usize,
) -> SystemPublicKeys<E> {
    SystemPublicKeys::new(public_keys, crs, lag_polys, positions_per_party)
}

pub fn aggregate_ciphertexts<E: Pairing>(ciphertexts: &[Ciphertext<E>]) -> Option<Ciphertext<E>> {
    let (first, rest) = ciphertexts.split_first()?;
    Some(rest.iter().fold(first.clone(), |acc, ciphertext| acc.add(ciphertext)))
}
