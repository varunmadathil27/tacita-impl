use serde::{Deserialize, Serialize};

pub type ClientId = u64;
pub type CommitteeMemberId = u64;
pub type RegistrationEpoch = u64;
pub type RoundId = u64;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaquePayload {
    pub bytes: Vec<u8>,
}

pub type OpaqueMklhtsVerificationKey = OpaquePayload;
pub type OpaqueMklhtsAggregateKeyMaterial = OpaquePayload;
pub type OpaqueMklhtsSignature = OpaquePayload;
pub type OpaqueMklhtsAggregateSignature = OpaquePayload;
pub type OpaqueMklhtsVerificationMaterial = OpaquePayload;

pub type OpaqueSteCommitteeKeyRegistration = OpaquePayload;
pub type OpaqueSteAggregateKeyMaterial = OpaquePayload;
pub type OpaqueSteCiphertext = OpaquePayload;
pub type OpaqueSteAggregateCiphertext = OpaquePayload;
pub type OpaqueStePartialDecryptionShare = OpaquePayload;
pub type OpaqueAggregatePlaintext = OpaquePayload;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSigningKeyRegistration<VerificationKey = OpaqueMklhtsVerificationKey> {
    pub registration_epoch: RegistrationEpoch,
    pub client_id: ClientId,
    pub verification_key: VerificationKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeEncryptionKeyRegistration<
    EncryptionKeyRegistration = OpaqueSteCommitteeKeyRegistration,
> {
    pub registration_epoch: RegistrationEpoch,
    pub committee_member_id: CommitteeMemberId,
    pub encryption_key_registration: EncryptionKeyRegistration,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeAggregateKeyMaterial<
    CommitteeEncryptionMaterial = OpaqueSteAggregateKeyMaterial,
    ClientVerificationMaterial = OpaqueMklhtsAggregateKeyMaterial,
> {
    pub registration_epoch: RegistrationEpoch,
    pub threshold: usize,
    pub committee_encryption_material: CommitteeEncryptionMaterial,
    pub client_verification_material: ClientVerificationMaterial,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSubmission<
    Ciphertext = OpaqueSteCiphertext,
    Signature = OpaqueMklhtsSignature,
> {
    pub round_id: RoundId,
    pub client_id: ClientId,
    pub ciphertext: Ciphertext,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerAggregateBundle<
    AggregateCiphertext = OpaqueSteAggregateCiphertext,
    AggregateSignature = OpaqueMklhtsAggregateSignature,
    VerificationMaterial = OpaqueMklhtsVerificationMaterial,
> {
    pub round_id: RoundId,
    pub included_clients: Vec<ClientId>,
    pub aggregate_ciphertext: AggregateCiphertext,
    pub aggregate_signature: AggregateSignature,
    pub verification_material: VerificationMaterial,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteePartialDecryption<
    PartialDecryptionShare = OpaqueStePartialDecryptionShare,
> {
    pub round_id: RoundId,
    pub committee_member_id: CommitteeMemberId,
    pub partial_decryption_share: PartialDecryptionShare,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerAggregateResult<AggregatePlaintext = OpaqueAggregatePlaintext> {
    pub round_id: RoundId,
    pub included_clients: Vec<ClientId>,
    pub aggregate_plaintext: AggregatePlaintext,
}
