use crate::{
    config::RoundConfig,
    errors::TacitaError,
    primitives::{MklhtsPrimitive, StePrimitive},
    types::{ClientId, ClientSigningKeyRegistration, ClientSubmission, CommitteeAggregateKeyMaterial, RegistrationEpoch},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Client {
    pub client_id: ClientId,
}

impl Client {
    pub fn new(client_id: ClientId) -> Self {
        Self { client_id }
    }

    pub fn register_signing_key<M: MklhtsPrimitive>(
        &self,
        registration_epoch: RegistrationEpoch,
        mklhts: &M,
    ) -> Result<ClientSigningKeyRegistration<M::ClientVerificationKey>, TacitaError> {
        let verification_key = mklhts
            .make_client_signing_key_registration(registration_epoch, self.client_id)
            .map_err(|err| TacitaError::primitive("mklhts", err))?;

        Ok(ClientSigningKeyRegistration {
            registration_epoch,
            client_id: self.client_id,
            verification_key,
        })
    }

    pub fn submit<S, M>(
        &self,
        round: &RoundConfig,
        aggregate_key_material: &CommitteeAggregateKeyMaterial<
            S::AggregateKeyMaterial,
            M::AggregateKeyMaterial,
        >,
        plaintext: &S::Plaintext,
        ste: &S,
        mklhts: &M,
    ) -> Result<ClientSubmission<S::Ciphertext, M::Signature>, TacitaError>
    where
        S: StePrimitive,
        M: MklhtsPrimitive,
    {
        let ciphertext = ste
            .encrypt(
                round.round_id,
                &aggregate_key_material.committee_encryption_material,
                plaintext,
            )
            .map_err(|err| TacitaError::primitive("ste", err))?;

        let signature = mklhts
            .sign_submission(
                round.round_id,
                self.client_id,
                &aggregate_key_material.client_verification_material,
                &ciphertext,
            )
            .map_err(|err| TacitaError::primitive("mklhts", err))?;

        Ok(ClientSubmission {
            round_id: round.round_id,
            client_id: self.client_id,
            ciphertext,
            signature,
        })
    }
}
