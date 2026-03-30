use crate::{
    config::RoundConfig,
    errors::TacitaError,
    primitives::{MklhtsPrimitive, StePrimitive},
    types::{
        CommitteeAggregateKeyMaterial, CommitteeEncryptionKeyRegistration, CommitteeMemberId,
        CommitteePartialDecryption, RegistrationEpoch, ServerAggregateBundle,
    },
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitteeMember {
    pub committee_member_id: CommitteeMemberId,
}

impl CommitteeMember {
    pub fn new(committee_member_id: CommitteeMemberId) -> Self {
        Self { committee_member_id }
    }

    pub fn register_encryption_key<S: StePrimitive>(
        &self,
        registration_epoch: RegistrationEpoch,
        ste: &S,
    ) -> Result<
        CommitteeEncryptionKeyRegistration<S::CommitteeEncryptionKeyRegistration>,
        TacitaError,
    > {
        let encryption_key_registration = ste
            .make_committee_encryption_key_registration(
                registration_epoch,
                self.committee_member_id,
            )
            .map_err(|err| TacitaError::primitive("ste", err))?;

        Ok(CommitteeEncryptionKeyRegistration {
            registration_epoch,
            committee_member_id: self.committee_member_id,
            encryption_key_registration,
        })
    }

    pub fn verify_and_partial_decrypt<S, M>(
        &self,
        round: &RoundConfig,
        aggregate_key_material: &CommitteeAggregateKeyMaterial<
            S::AggregateKeyMaterial,
            M::AggregateKeyMaterial,
        >,
        aggregate_bundle: &ServerAggregateBundle<
            S::AggregateCiphertext,
            M::AggregateSignature,
            M::VerificationMaterial,
        >,
        ste: &S,
        mklhts: &M,
    ) -> Result<CommitteePartialDecryption<S::PartialDecryptionShare>, TacitaError>
    where
        S: StePrimitive,
        M: MklhtsPrimitive,
    {
        mklhts
            .verify_aggregate_signature(
                round.round_id,
                &aggregate_key_material.client_verification_material,
                aggregate_bundle,
            )
            .map_err(|err| TacitaError::primitive("mklhts", err))?;

        let partial_decryption_share = ste
            .partial_decrypt(
                round.round_id,
                self.committee_member_id,
                &aggregate_key_material.committee_encryption_material,
                &aggregate_bundle.aggregate_ciphertext,
            )
            .map_err(|err| TacitaError::primitive("ste", err))?;

        Ok(CommitteePartialDecryption {
            round_id: round.round_id,
            committee_member_id: self.committee_member_id,
            partial_decryption_share,
        })
    }
}
