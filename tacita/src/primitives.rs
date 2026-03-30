use std::fmt::Display;

use crate::types::{
    ClientId, ClientSigningKeyRegistration, ClientSubmission, CommitteeEncryptionKeyRegistration,
    CommitteeMemberId, CommitteePartialDecryption, RegistrationEpoch, RoundId,
    ServerAggregateBundle,
};

pub trait StePrimitive {
    type Error: Display + Send + Sync + 'static;
    type CommitteeEncryptionKeyRegistration: Clone + Send + Sync + 'static;
    type AggregateKeyMaterial: Clone + Send + Sync + 'static;
    type Plaintext: Clone + Send + Sync + 'static;
    type Ciphertext: Clone + Send + Sync + 'static;
    type AggregateCiphertext: Clone + Send + Sync + 'static;
    type PartialDecryptionShare: Clone + Send + Sync + 'static;

    fn make_committee_encryption_key_registration(
        &self,
        registration_epoch: RegistrationEpoch,
        committee_member_id: CommitteeMemberId,
    ) -> Result<Self::CommitteeEncryptionKeyRegistration, Self::Error>;

    fn derive_committee_aggregate_key_material(
        &self,
        registrations: &[CommitteeEncryptionKeyRegistration<Self::CommitteeEncryptionKeyRegistration>],
        threshold: usize,
    ) -> Result<Self::AggregateKeyMaterial, Self::Error>;

    fn encrypt(
        &self,
        round_id: RoundId,
        aggregate_key_material: &Self::AggregateKeyMaterial,
        plaintext: &Self::Plaintext,
    ) -> Result<Self::Ciphertext, Self::Error>;

    fn aggregate_ciphertexts(
        &self,
        ciphertexts: &[Self::Ciphertext],
    ) -> Result<Self::AggregateCiphertext, Self::Error>;

    fn partial_decrypt(
        &self,
        round_id: RoundId,
        committee_member_id: CommitteeMemberId,
        aggregate_key_material: &Self::AggregateKeyMaterial,
        aggregate_ciphertext: &Self::AggregateCiphertext,
    ) -> Result<Self::PartialDecryptionShare, Self::Error>;

    fn finalize_decryption(
        &self,
        round_id: RoundId,
        aggregate_key_material: &Self::AggregateKeyMaterial,
        aggregate_ciphertext: &Self::AggregateCiphertext,
        shares: &[CommitteePartialDecryption<Self::PartialDecryptionShare>],
    ) -> Result<Self::Plaintext, Self::Error>;
}

pub trait MklhtsPrimitive {
    type Error: Display + Send + Sync + 'static;
    type ClientVerificationKey: Clone + Send + Sync + 'static;
    type AggregateKeyMaterial: Clone + Send + Sync + 'static;
    type Signature: Clone + Send + Sync + 'static;
    type AggregateSignature: Clone + Send + Sync + 'static;
    type VerificationMaterial: Clone + Send + Sync + 'static;

    fn make_client_signing_key_registration(
        &self,
        registration_epoch: RegistrationEpoch,
        client_id: ClientId,
    ) -> Result<Self::ClientVerificationKey, Self::Error>;

    fn derive_client_aggregate_key_material(
        &self,
        registrations: &[ClientSigningKeyRegistration<Self::ClientVerificationKey>],
        threshold: usize,
    ) -> Result<Self::AggregateKeyMaterial, Self::Error>;

    fn sign_submission<Payload>(
        &self,
        round_id: RoundId,
        client_id: ClientId,
        aggregate_key_material: &Self::AggregateKeyMaterial,
        payload: &Payload,
    ) -> Result<Self::Signature, Self::Error>
    where
        Payload: Clone + Send + Sync + 'static;

    fn aggregate_signatures<Payload>(
        &self,
        round_id: RoundId,
        aggregate_key_material: &Self::AggregateKeyMaterial,
        submissions: &[ClientSubmission<Payload, Self::Signature>],
    ) -> Result<(Self::AggregateSignature, Self::VerificationMaterial), Self::Error>
    where
        Payload: Clone + Send + Sync + 'static;

    fn verify_aggregate_signature<Payload>(
        &self,
        round_id: RoundId,
        aggregate_key_material: &Self::AggregateKeyMaterial,
        bundle: &ServerAggregateBundle<Payload, Self::AggregateSignature, Self::VerificationMaterial>,
    ) -> Result<(), Self::Error>
    where
        Payload: Clone + Send + Sync + 'static;
}
