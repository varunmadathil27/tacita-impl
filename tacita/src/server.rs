use crate::{
    config::RoundConfig,
    errors::TacitaError,
    primitives::{MklhtsPrimitive, StePrimitive},
    types::{
        ClientSubmission, CommitteeAggregateKeyMaterial, CommitteePartialDecryption,
        ServerAggregateBundle, ServerAggregateResult,
    },
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Server;

impl Server {
    pub fn new() -> Self {
        Self
    }

    pub fn aggregate_submissions<S, M>(
        &self,
        round: &RoundConfig,
        aggregate_key_material: &CommitteeAggregateKeyMaterial<
            S::AggregateKeyMaterial,
            M::AggregateKeyMaterial,
        >,
        submissions: &[ClientSubmission<S::Ciphertext, M::Signature>],
        ste: &S,
        mklhts: &M,
    ) -> Result<
        ServerAggregateBundle<
            S::AggregateCiphertext,
            M::AggregateSignature,
            M::VerificationMaterial,
        >,
        TacitaError,
    >
    where
        S: StePrimitive,
        M: MklhtsPrimitive,
    {
        if submissions.is_empty() {
            return Err(TacitaError::Validation {
                message: "server aggregation requires at least one client submission",
            });
        }

        let ciphertexts = submissions
            .iter()
            .map(|submission| submission.ciphertext.clone())
            .collect::<Vec<_>>();

        let aggregate_ciphertext = ste
            .aggregate_ciphertexts(&ciphertexts)
            .map_err(|err| TacitaError::primitive("ste", err))?;

        let (aggregate_signature, verification_material) = mklhts
            .aggregate_signatures(
                round.round_id,
                &aggregate_key_material.client_verification_material,
                submissions,
            )
            .map_err(|err| TacitaError::primitive("mklhts", err))?;

        Ok(ServerAggregateBundle {
            round_id: round.round_id,
            included_clients: submissions.iter().map(|submission| submission.client_id).collect(),
            aggregate_ciphertext,
            aggregate_signature,
            verification_material,
        })
    }

    pub fn finalize_result<S, M>(
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
        partial_decryptions: &[CommitteePartialDecryption<S::PartialDecryptionShare>],
        ste: &S,
    ) -> Result<ServerAggregateResult<S::Plaintext>, TacitaError>
    where
        S: StePrimitive,
        M: MklhtsPrimitive,
    {
        let aggregate_plaintext = ste
            .finalize_decryption(
                round.round_id,
                &aggregate_key_material.committee_encryption_material,
                &aggregate_bundle.aggregate_ciphertext,
                partial_decryptions,
            )
            .map_err(|err| TacitaError::primitive("ste", err))?;

        Ok(ServerAggregateResult {
            round_id: round.round_id,
            included_clients: aggregate_bundle.included_clients.clone(),
            aggregate_plaintext,
        })
    }
}
