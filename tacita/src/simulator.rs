use std::{
    any::Any,
    collections::{BTreeMap, BTreeSet},
    fmt::{Debug, Display, Formatter},
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{Arc, Mutex},
};

use ark_bls12_381::{Bls12_381 as SteCurve, Fr as SteScalar};
use ark_ec::{
    pairing::PairingOutput,
    PrimeGroup,
};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng as StdRng05, SeedableRng as SeedableRng05};
use hints::{
    kzg::UniversalParams,
    protocol::empty_client_signature,
    prove::prove,
    setup::{prepare_cache, setup},
    signer::sign,
    types::{
        Cache as HintsCache, ClientSignature as HintsClientSignature, F as HintsField,
        Proof as HintsProof, ProverPreprocessing, VerifierPreprocessing,
    },
    verify::verify as verify_hints_proof,
};
use rand08::{rngs::StdRng as StdRng08, RngCore as RngCore08};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    client::Client,
    committee::CommitteeMember,
    config::{ProtocolConfig, RoundConfig},
    errors::TacitaError,
    primitives::{MklhtsPrimitive, StePrimitive},
    server::Server,
    types::{
        ClientId, ClientSigningKeyRegistration, ClientSubmission, CommitteeAggregateKeyMaterial,
        CommitteeEncryptionKeyRegistration, CommitteeMemberId, CommitteePartialDecryption,
        RegistrationEpoch, RoundId, ServerAggregateBundle, ServerAggregateResult,
    },
};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptLog {
    pub events: Vec<TranscriptEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptEvent {
    pub stage: String,
    pub detail: String,
}

impl TranscriptLog {
    fn push(&mut self, stage: &'static str, detail: impl Into<String>) {
        self.events.push(TranscriptEvent {
            stage: stage.to_string(),
            detail: detail.into(),
        });
    }
}

#[derive(Clone, Debug)]
pub struct OfflineArtifacts<
    CommitteeRegistration,
    ClientVerificationKey,
    CommitteeEncryptionMaterial,
    ClientVerificationMaterial,
> {
    pub client_registrations: Vec<ClientSigningKeyRegistration<ClientVerificationKey>>,
    pub committee_registrations: Vec<CommitteeEncryptionKeyRegistration<CommitteeRegistration>>,
    pub aggregate_key_material: CommitteeAggregateKeyMaterial<
        CommitteeEncryptionMaterial,
        ClientVerificationMaterial,
    >,
    pub transcript: TranscriptLog,
}

#[derive(Clone, Debug)]
pub struct OnlineRoundOutcome<AggregatePlaintext> {
    pub result: ServerAggregateResult<AggregatePlaintext>,
    pub transcript: TranscriptLog,
}

#[derive(Clone, Debug)]
pub struct SingleProcessSimulator<S, M> {
    pub protocol: ProtocolConfig,
    pub ste: S,
    pub mklhts: M,
    pub server: Server,
}

impl<S, M> SingleProcessSimulator<S, M>
where
    S: StePrimitive,
    M: MklhtsPrimitive,
{
    pub fn new(protocol: ProtocolConfig, ste: S, mklhts: M) -> Self {
        Self {
            protocol,
            ste,
            mklhts,
            server: Server::new(),
        }
    }

    pub fn prepare_offline_phase(
        &self,
        clients: &[Client],
        committee_members: &[CommitteeMember],
    ) -> Result<
        OfflineArtifacts<
            S::CommitteeEncryptionKeyRegistration,
            M::ClientVerificationKey,
            S::AggregateKeyMaterial,
            M::AggregateKeyMaterial,
        >,
        TacitaError,
    > {
        if clients.is_empty() {
            return Err(TacitaError::MissingRegistration { role: "client" });
        }
        if committee_members.is_empty() {
            return Err(TacitaError::MissingRegistration { role: "committee" });
        }

        let mut transcript = TranscriptLog::default();
        transcript.push(
            "offline-config",
            format!(
                "registration_epoch={}, threshold={}, expected_clients={}, committee_size={}",
                self.protocol.registration_epoch,
                self.protocol.threshold,
                self.protocol.expected_clients,
                self.protocol.committee_size
            ),
        );

        let client_registrations = clients
            .iter()
            .map(|client| {
                client.register_signing_key(self.protocol.registration_epoch, &self.mklhts)
            })
            .collect::<Result<Vec<_>, _>>()?;
        ensure(
            client_registrations.len() == clients.len(),
            "offline-client-registration-count",
        )?;
        ensure_unique_client_ids(&client_registrations)?;
        transcript.push(
            "offline-client-registration",
            format!("registered {} client signing keys", client_registrations.len()),
        );

        let committee_registrations = committee_members
            .iter()
            .map(|member| {
                member.register_encryption_key(self.protocol.registration_epoch, &self.ste)
            })
            .collect::<Result<Vec<_>, _>>()?;
        ensure(
            committee_registrations.len() == committee_members.len(),
            "offline-committee-registration-count",
        )?;
        ensure_unique_committee_ids(&committee_registrations)?;
        transcript.push(
            "offline-committee-registration",
            format!(
                "registered {} committee encryption keys",
                committee_registrations.len()
            ),
        );

        let aggregate_key_material = self.derive_committee_aggregate_key_material(
            &client_registrations,
            &committee_registrations,
        )?;
        ensure(
            aggregate_key_material.threshold == self.protocol.threshold,
            "offline-threshold-consistency",
        )?;
        transcript.push(
            "offline-aggregate-material",
            format!(
                "derived aggregate material for {} clients and {} committee members",
                client_registrations.len(),
                committee_registrations.len()
            ),
        );

        Ok(OfflineArtifacts {
            client_registrations,
            committee_registrations,
            aggregate_key_material,
            transcript,
        })
    }

    pub fn derive_committee_aggregate_key_material(
        &self,
        client_registrations: &[ClientSigningKeyRegistration<M::ClientVerificationKey>],
        committee_registrations: &[CommitteeEncryptionKeyRegistration<S::CommitteeEncryptionKeyRegistration>],
    ) -> Result<
        CommitteeAggregateKeyMaterial<S::AggregateKeyMaterial, M::AggregateKeyMaterial>,
        TacitaError,
    > {
        if client_registrations.is_empty() {
            return Err(TacitaError::MissingRegistration { role: "client" });
        }
        if committee_registrations.is_empty() {
            return Err(TacitaError::MissingRegistration { role: "committee" });
        }

        let committee_encryption_material = self
            .ste
            .derive_committee_aggregate_key_material(
                committee_registrations,
                self.protocol.threshold,
            )
            .map_err(|err| TacitaError::primitive("ste", err))?;

        let client_verification_material = self
            .mklhts
            .derive_client_aggregate_key_material(client_registrations, self.protocol.threshold)
            .map_err(|err| TacitaError::primitive("mklhts", err))?;

        Ok(CommitteeAggregateKeyMaterial {
            registration_epoch: self.protocol.registration_epoch,
            threshold: self.protocol.threshold,
            committee_encryption_material,
            client_verification_material,
        })
    }

    pub fn simulate_online_round(
        &self,
        round: &RoundConfig,
        offline: &OfflineArtifacts<
            S::CommitteeEncryptionKeyRegistration,
            M::ClientVerificationKey,
            S::AggregateKeyMaterial,
            M::AggregateKeyMaterial,
        >,
        client_inputs: &[(Client, S::Plaintext)],
        committee_members: &[CommitteeMember],
    ) -> Result<OnlineRoundOutcome<S::Plaintext>, TacitaError> {
        if client_inputs.is_empty() {
            return Err(TacitaError::Validation {
                message: "single-process simulation requires at least one client input",
            });
        }
        if committee_members.len() < round.threshold {
            return Err(TacitaError::Validation {
                message: "simulation requires at least threshold committee members",
            });
        }

        let mut transcript = TranscriptLog::default();
        transcript.push(
            "online-config",
            format!(
                "round_id={}, threshold={}, client_inputs={}, committee_online={}",
                round.round_id,
                round.threshold,
                client_inputs.len(),
                committee_members.len()
            ),
        );

        let submissions = client_inputs
            .iter()
            .map(|(client, plaintext)| {
                client.submit(
                    round,
                    &offline.aggregate_key_material,
                    plaintext,
                    &self.ste,
                    &self.mklhts,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        ensure(
            submissions.iter().all(|submission| submission.round_id == round.round_id),
            "stage1-round-binding",
        )?;
        ensure(
            submissions.len() == client_inputs.len(),
            "stage1-submission-count",
        )?;
        transcript.push(
            "client-encrypt-and-sign",
            format!("produced {} client submissions", submissions.len()),
        );

        let aggregate_bundle = self.server.aggregate_submissions(
            round,
            &offline.aggregate_key_material,
            &submissions,
            &self.ste,
            &self.mklhts,
        )?;
        ensure(
            aggregate_bundle.round_id == round.round_id,
            "stage2-round-binding",
        )?;
        ensure(
            aggregate_bundle.included_clients.len() == submissions.len(),
            "stage2-included-client-count",
        )?;
        transcript.push(
            "server-aggregate",
            format!(
                "aggregated {} submissions into one bundle",
                aggregate_bundle.included_clients.len()
            ),
        );

        let partial_decryptions = committee_members
            .iter()
            .map(|member| {
                member.verify_and_partial_decrypt(
                    round,
                    &offline.aggregate_key_material,
                    &aggregate_bundle,
                    &self.ste,
                    &self.mklhts,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        ensure(
            partial_decryptions.len() >= round.threshold,
            "stage3-threshold-shares",
        )?;
        ensure(
            partial_decryptions
                .iter()
                .all(|share| share.round_id == round.round_id),
            "stage3-round-binding",
        )?;
        transcript.push(
            "committee-verify-and-partial-decrypt",
            format!("verified bundle and emitted {} decryption shares", partial_decryptions.len()),
        );

        let result = self.server.finalize_result::<S, M>(
            round,
            &offline.aggregate_key_material,
            &aggregate_bundle,
            &partial_decryptions,
            &self.ste,
        )?;
        ensure(result.round_id == round.round_id, "stage4-round-binding")?;
        ensure(
            result.included_clients == aggregate_bundle.included_clients,
            "stage4-client-set-consistency",
        )?;
        transcript.push(
            "server-finalize",
            format!(
                "finalized aggregate result for {} included clients",
                result.included_clients.len()
            ),
        );

        Ok(OnlineRoundOutcome { result, transcript })
    }

    pub fn simulate_round(
        &self,
        round: &RoundConfig,
        aggregate_key_material: &CommitteeAggregateKeyMaterial<
            S::AggregateKeyMaterial,
            M::AggregateKeyMaterial,
        >,
        client_inputs: &[(Client, S::Plaintext)],
        committee_members: &[CommitteeMember],
    ) -> Result<ServerAggregateResult<S::Plaintext>, TacitaError> {
        let offline = OfflineArtifacts {
            client_registrations: Vec::new(),
            committee_registrations: Vec::new(),
            aggregate_key_material: aggregate_key_material.clone(),
            transcript: TranscriptLog::default(),
        };
        self.simulate_online_round(round, &offline, client_inputs, committee_members)
            .map(|outcome| outcome.result)
    }
}

fn ensure(condition: bool, message: &'static str) -> Result<(), TacitaError> {
    if condition {
        Ok(())
    } else {
        Err(TacitaError::Validation { message })
    }
}

fn ensure_unique_client_ids<V>(
    registrations: &[ClientSigningKeyRegistration<V>],
) -> Result<(), TacitaError> {
    let unique = registrations
        .iter()
        .map(|registration| registration.client_id)
        .collect::<BTreeSet<_>>();
    ensure(unique.len() == registrations.len(), "offline-duplicate-client-ids")
}

fn ensure_unique_committee_ids<V>(
    registrations: &[CommitteeEncryptionKeyRegistration<V>],
) -> Result<(), TacitaError> {
    let unique = registrations
        .iter()
        .map(|registration| registration.committee_member_id)
        .collect::<BTreeSet<_>>();
    ensure(
        unique.len() == registrations.len(),
        "offline-duplicate-committee-ids",
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToyPlaintext {
    pub slots: Vec<u64>,
}

impl ToyPlaintext {
    pub fn new(slots: Vec<u64>) -> Self {
        Self { slots }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ToySteCiphertext {
    pub inner: ste::encryption::Ciphertext<SteCurve>,
    pub transcript_bytes: Vec<u8>,
    pub slot_count: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ToySteAggregateCiphertext {
    pub inner: ste::encryption::Ciphertext<SteCurve>,
    pub transcript_bytes: Vec<u8>,
    pub slot_count: usize,
    pub contributor_count: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ToyStePartialDecryptionShare {
    pub inner: ste::partial_decryption::PartialDecryption<SteCurve>,
}

#[derive(Clone)]
pub struct ToyCommitteeEncryptionKeyRegistration {
    pub committee_member_id: CommitteeMemberId,
    pub position: usize,
    pub lag_public_key: ste::setup::LagPublicKey<SteCurve>,
}

#[derive(Clone)]
pub struct ToySteAggregateKeyMaterial {
    pub crs: ste::setup::CRS<SteCurve>,
    pub aggregate_key: ste::aggregation::AggregateKey<SteCurve>,
    pub encryption_key: ste::aggregation::EncryptionKey<SteCurve>,
    pub committee_positions: BTreeMap<CommitteeMemberId, usize>,
    pub threshold: usize,
    pub max_discrete_log: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ToyClientVerificationKey {
    pub client_id: ClientId,
    pub slot: usize,
    pub public_key: hints::types::G1,
}

#[derive(Clone)]
pub struct ToyMklhtsAggregateKeyMaterial {
    pub params: Arc<UniversalParams<ark_bls12_381_04::Bls12_381>>,
    pub verifier: VerifierPreprocessing,
    pub prover: ProverPreprocessing,
    pub cache: HintsCache,
    pub weights: Vec<HintsField>,
    pub client_slots: BTreeMap<ClientId, usize>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ToySignature {
    pub inner: HintsClientSignature,
    pub message_scalar: HintsField,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ToyAggregateSignature {
    pub proof: HintsProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToyVerificationMaterial {
    pub bitmap: Vec<bool>,
}

#[derive(Clone, Debug)]
pub struct ToySteConfig {
    pub committee_size: usize,
    pub slot_count: usize,
    pub threshold: usize,
    pub seed: u64,
    pub max_discrete_log: u64,
}

#[derive(Clone, Debug)]
pub struct ToyMklhtsConfig {
    pub expected_clients: usize,
    pub seed: u64,
}

#[derive(Clone)]
pub struct ToySteBackend {
    state: Arc<ToySteState>,
}

#[derive(Clone)]
struct ToySteState {
    committee_size: usize,
    slot_count: usize,
    seed: u64,
    max_discrete_log: u64,
    crs: ste::setup::CRS<SteCurve>,
    secret_keys: BTreeMap<CommitteeMemberId, ste::setup::SecretKey<SteCurve>>,
    lag_public_keys: BTreeMap<CommitteeMemberId, ste::setup::LagPublicKey<SteCurve>>,
    encrypt_nonce: Arc<Mutex<u64>>,
}

#[derive(Clone)]
pub struct ToyMklhtsBackend {
    state: Arc<ToyMklhtsState>,
}

#[derive(Clone)]
struct ToyMklhtsState {
    expected_clients: usize,
    params: Arc<UniversalParams<ark_bls12_381_04::Bls12_381>>,
    verifier: VerifierPreprocessing,
    prover: ProverPreprocessing,
    cache: HintsCache,
    weights: Vec<HintsField>,
    secret_keys: BTreeMap<ClientId, HintsField>,
    client_slots: BTreeMap<ClientId, usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToyBackendError {
    InvalidConfig(&'static str),
    UnknownClient(ClientId),
    UnknownCommitteeMember(CommitteeMemberId),
    WrongPayloadType(&'static str),
    Serialization(&'static str),
    VerificationFailed(&'static str),
    DecodeFailed(&'static str),
}

impl Display for ToyBackendError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(f, "invalid config: {message}"),
            Self::UnknownClient(client_id) => write!(f, "unknown client id {client_id}"),
            Self::UnknownCommitteeMember(member_id) => {
                write!(f, "unknown committee member id {member_id}")
            }
            Self::WrongPayloadType(message) => write!(f, "wrong payload type: {message}"),
            Self::Serialization(message) => write!(f, "serialization failed: {message}"),
            Self::VerificationFailed(message) => write!(f, "verification failed: {message}"),
            Self::DecodeFailed(message) => write!(f, "decode failed: {message}"),
        }
    }
}

impl ToySteBackend {
    pub fn new(config: ToySteConfig) -> Result<Self, ToyBackendError> {
        if !config.committee_size.is_power_of_two() {
            return Err(ToyBackendError::InvalidConfig(
                "committee_size must be a power of two for STE CRS generation",
            ));
        }
        if config.threshold == 0 || config.threshold > config.committee_size {
            return Err(ToyBackendError::InvalidConfig(
                "threshold must be in 1..=committee_size",
            ));
        }
        if config.slot_count == 0 {
            return Err(ToyBackendError::InvalidConfig(
                "slot_count must be positive",
            ));
        }

        let mut rng = StdRng05::seed_from_u64(config.seed);
        let crs = ste::setup::CRS::<SteCurve>::new(config.committee_size, config.slot_count, &mut rng);
        let mut secret_keys = BTreeMap::new();
        let mut lag_public_keys = BTreeMap::new();

        for position in 0..config.committee_size {
            let member_id = position as CommitteeMemberId;
            let secret_key = ste::setup::SecretKey::<SteCurve>::new(&mut rng, position);
            let lag_public_key = secret_key.get_lagrange_pk(position, &crs);
            secret_keys.insert(member_id, secret_key);
            lag_public_keys.insert(member_id, lag_public_key);
        }

        Ok(Self {
            state: Arc::new(ToySteState {
                committee_size: config.committee_size,
                slot_count: config.slot_count,
                seed: config.seed,
                max_discrete_log: config.max_discrete_log,
                crs,
                secret_keys,
                lag_public_keys,
                encrypt_nonce: Arc::new(Mutex::new(0)),
            }),
        })
    }

    fn encode_plaintext(
        &self,
        plaintext: &ToyPlaintext,
    ) -> Result<Vec<PairingOutput<SteCurve>>, ToyBackendError> {
        if plaintext.slots.len() != self.state.slot_count {
            return Err(ToyBackendError::InvalidConfig(
                "plaintext slot count must match STE slot count",
            ));
        }

        Ok(plaintext
            .slots
            .iter()
            .map(|slot| PairingOutput::<SteCurve>::generator() * SteScalar::from(*slot))
            .collect())
    }

    fn decode_plaintext(
        &self,
        encoded: &[PairingOutput<SteCurve>],
    ) -> Result<ToyPlaintext, ToyBackendError> {
        if encoded.len() != self.state.slot_count {
            return Err(ToyBackendError::DecodeFailed("unexpected slot count"));
        }

        let mut slots = Vec::with_capacity(encoded.len());
        for value in encoded {
            let mut decoded = None;
            for candidate in 0..=self.state.max_discrete_log {
                let expected = PairingOutput::<SteCurve>::generator() * SteScalar::from(candidate);
                if &expected == value {
                    decoded = Some(candidate);
                    break;
                }
            }
            let slot = decoded.ok_or(ToyBackendError::DecodeFailed(
                "aggregate plaintext is outside the configured toy discrete log bound",
            ))?;
            slots.push(slot);
        }

        Ok(ToyPlaintext { slots })
    }
}

impl StePrimitive for ToySteBackend {
    type Error = ToyBackendError;
    type CommitteeEncryptionKeyRegistration = ToyCommitteeEncryptionKeyRegistration;
    type AggregateKeyMaterial = ToySteAggregateKeyMaterial;
    type Plaintext = ToyPlaintext;
    type Ciphertext = ToySteCiphertext;
    type AggregateCiphertext = ToySteAggregateCiphertext;
    type PartialDecryptionShare = ToyStePartialDecryptionShare;

    fn make_committee_encryption_key_registration(
        &self,
        _registration_epoch: RegistrationEpoch,
        committee_member_id: CommitteeMemberId,
    ) -> Result<Self::CommitteeEncryptionKeyRegistration, Self::Error> {
        let lag_public_key = self
            .state
            .lag_public_keys
            .get(&committee_member_id)
            .cloned()
            .ok_or(ToyBackendError::UnknownCommitteeMember(committee_member_id))?;
        let position = committee_member_id as usize;
        Ok(ToyCommitteeEncryptionKeyRegistration {
            committee_member_id,
            position,
            lag_public_key,
        })
    }

    fn derive_committee_aggregate_key_material(
        &self,
        registrations: &[CommitteeEncryptionKeyRegistration<Self::CommitteeEncryptionKeyRegistration>],
        threshold: usize,
    ) -> Result<Self::AggregateKeyMaterial, Self::Error> {
        let lag_public_keys = registrations
            .iter()
            .map(|registration| registration.encryption_key_registration.lag_public_key.clone())
            .collect::<Vec<_>>();
        let committee_positions = registrations
            .iter()
            .map(|registration| {
                (
                    registration.committee_member_id,
                    registration.encryption_key_registration.position,
                )
            })
            .collect::<BTreeMap<_, _>>();
        let (aggregate_key, encryption_key) =
            ste::aggregation::aggregate_key_material(lag_public_keys, &self.state.crs);

        Ok(ToySteAggregateKeyMaterial {
            crs: self.state.crs.clone(),
            aggregate_key,
            encryption_key,
            committee_positions,
            threshold,
            max_discrete_log: self.state.max_discrete_log,
        })
    }

    fn encrypt(
        &self,
        round_id: RoundId,
        aggregate_key_material: &Self::AggregateKeyMaterial,
        plaintext: &Self::Plaintext,
    ) -> Result<Self::Ciphertext, Self::Error> {
        let encoded = self.encode_plaintext(plaintext)?;
        let nonce = {
            let mut guard = self.state.encrypt_nonce.lock().unwrap();
            let current = *guard;
            *guard += 1;
            current
        };
        let mut rng = StdRng05::seed_from_u64(mix_seed(self.state.seed, round_id, nonce));
        let ciphertext = ste::encryption::encrypt(
            &aggregate_key_material.encryption_key,
            aggregate_key_material.threshold,
            &aggregate_key_material.crs,
            &encoded,
            &mut rng,
        );
        let transcript_bytes = serialize_ste(&ciphertext)?;

        Ok(ToySteCiphertext {
            inner: ciphertext,
            transcript_bytes,
            slot_count: plaintext.slots.len(),
        })
    }

    fn aggregate_ciphertexts(
        &self,
        ciphertexts: &[Self::Ciphertext],
    ) -> Result<Self::AggregateCiphertext, Self::Error> {
        let inners = ciphertexts
            .iter()
            .map(|ciphertext| ciphertext.inner.clone())
            .collect::<Vec<_>>();
        let aggregated = ste::aggregation::aggregate_ciphertexts(&inners)
            .ok_or(ToyBackendError::InvalidConfig(
                "aggregate_ciphertexts requires at least one ciphertext",
            ))?;
        let transcript_bytes = serialize_ste(&aggregated)?;

        Ok(ToySteAggregateCiphertext {
            inner: aggregated,
            transcript_bytes,
            slot_count: ciphertexts[0].slot_count,
            contributor_count: ciphertexts.len(),
        })
    }

    fn partial_decrypt(
        &self,
        _round_id: RoundId,
        committee_member_id: CommitteeMemberId,
        _aggregate_key_material: &Self::AggregateKeyMaterial,
        aggregate_ciphertext: &Self::AggregateCiphertext,
    ) -> Result<Self::PartialDecryptionShare, Self::Error> {
        let secret_key = self
            .state
            .secret_keys
            .get(&committee_member_id)
            .ok_or(ToyBackendError::UnknownCommitteeMember(committee_member_id))?;

        Ok(ToyStePartialDecryptionShare {
            inner: ste::partial_decryption::compute_partial_decryption(
                secret_key,
                &aggregate_ciphertext.inner,
            ),
        })
    }

    fn finalize_decryption(
        &self,
        _round_id: RoundId,
        aggregate_key_material: &Self::AggregateKeyMaterial,
        aggregate_ciphertext: &Self::AggregateCiphertext,
        shares: &[CommitteePartialDecryption<Self::PartialDecryptionShare>],
    ) -> Result<Self::Plaintext, Self::Error> {
        if shares.len() < aggregate_key_material.threshold {
            return Err(ToyBackendError::InvalidConfig(
                "finalize_decryption requires at least threshold shares",
            ));
        }

        let mut selector = vec![false; self.state.committee_size];
        let mut ordered_shares =
            vec![ste::partial_decryption::zero_partial_decryption::<SteCurve>(); self.state.committee_size];

        for share in shares {
            let position = aggregate_key_material
                .committee_positions
                .get(&share.committee_member_id)
                .copied()
                .ok_or(ToyBackendError::UnknownCommitteeMember(
                    share.committee_member_id,
                ))?;
            selector[position] = true;
            ordered_shares[position] = share.partial_decryption_share.inner.clone();
        }

        let recovered = ste::final_decryption::finalize_decryption(
            &ordered_shares,
            &aggregate_ciphertext.inner,
            &selector,
            &aggregate_key_material.aggregate_key,
            &aggregate_key_material.crs,
        );
        self.decode_plaintext(&recovered)
    }
}

impl ToyMklhtsBackend {
    pub fn new(config: ToyMklhtsConfig) -> Result<Self, ToyBackendError> {
        let n = config.expected_clients + 1;
        if !n.is_power_of_two() {
            return Err(ToyBackendError::InvalidConfig(
                "expected_clients + 1 must be a power of two for the current hints setup",
            ));
        }

        let mut rng = StdRng08::seed_from_u64(config.seed);
        let params = Arc::new(
            hints::types::KZG::setup(n, &mut rng)
                .map_err(|_| ToyBackendError::InvalidConfig("hints KZG setup failed"))?,
        );
        let cache = prepare_cache(n);

        let mut secret_keys = BTreeMap::new();
        let mut client_slots = BTreeMap::new();
        let mut sk_values = Vec::with_capacity(config.expected_clients);
        let mut weights = Vec::with_capacity(config.expected_clients);

        for slot in 0..config.expected_clients {
            let client_id = slot as ClientId;
            let sk = HintsField::from(rng.next_u64());
            secret_keys.insert(client_id, sk);
            client_slots.insert(client_id, slot);
            sk_values.push(sk);
            weights.push(HintsField::from((slot as u64) + 1));
        }

        let (verifier, prover) = setup(n, &params, &weights, &sk_values);

        Ok(Self {
            state: Arc::new(ToyMklhtsState {
                expected_clients: config.expected_clients,
                params,
                verifier,
                prover,
                cache,
                weights,
                secret_keys,
                client_slots,
            }),
        })
    }
}

impl MklhtsPrimitive for ToyMklhtsBackend {
    type Error = ToyBackendError;
    type ClientVerificationKey = ToyClientVerificationKey;
    type AggregateKeyMaterial = ToyMklhtsAggregateKeyMaterial;
    type Signature = ToySignature;
    type AggregateSignature = ToyAggregateSignature;
    type VerificationMaterial = ToyVerificationMaterial;

    fn make_client_signing_key_registration(
        &self,
        _registration_epoch: RegistrationEpoch,
        client_id: ClientId,
    ) -> Result<Self::ClientVerificationKey, Self::Error> {
        let slot = self
            .state
            .client_slots
            .get(&client_id)
            .copied()
            .ok_or(ToyBackendError::UnknownClient(client_id))?;
        Ok(ToyClientVerificationKey {
            client_id,
            slot,
            public_key: self.state.prover.pks[slot],
        })
    }

    fn derive_client_aggregate_key_material(
        &self,
        registrations: &[ClientSigningKeyRegistration<Self::ClientVerificationKey>],
        _threshold: usize,
    ) -> Result<Self::AggregateKeyMaterial, Self::Error> {
        let client_slots = registrations
            .iter()
            .map(|registration| {
                (
                    registration.client_id,
                    registration.verification_key.slot,
                )
            })
            .collect::<BTreeMap<_, _>>();

        Ok(ToyMklhtsAggregateKeyMaterial {
            params: self.state.params.clone(),
            verifier: self.state.verifier.clone(),
            prover: self.state.prover.clone(),
            cache: self.state.cache.clone(),
            weights: self.state.weights.clone(),
            client_slots,
        })
    }

    fn sign_submission<Payload>(
        &self,
        _round_id: RoundId,
        client_id: ClientId,
        aggregate_key_material: &Self::AggregateKeyMaterial,
        payload: &Payload,
    ) -> Result<Self::Signature, Self::Error>
    where
        Payload: Clone + Send + Sync + 'static,
    {
        let ciphertext = (payload as &dyn Any)
            .downcast_ref::<ToySteCiphertext>()
            .ok_or(ToyBackendError::WrongPayloadType(
                "toy MKLHTS backend expects ToySteCiphertext payloads",
            ))?;
        let slot = aggregate_key_material
            .client_slots
            .get(&client_id)
            .copied()
            .ok_or(ToyBackendError::UnknownClient(client_id))?;
        let secret_key = self
            .state
            .secret_keys
            .get(&client_id)
            .ok_or(ToyBackendError::UnknownClient(client_id))?;
        let message_scalar = hash_bytes_to_hints_field(&ciphertext.transcript_bytes);
        let signature = sign(
            &aggregate_key_material.params,
            &aggregate_key_material.prover,
            secret_key,
            &aggregate_key_material.verifier.h_0,
            &message_scalar,
            slot,
        );

        Ok(ToySignature {
            inner: signature,
            message_scalar,
        })
    }

    fn aggregate_signatures<Payload>(
        &self,
        _round_id: RoundId,
        aggregate_key_material: &Self::AggregateKeyMaterial,
        submissions: &[ClientSubmission<Payload, Self::Signature>],
    ) -> Result<(Self::AggregateSignature, Self::VerificationMaterial), Self::Error>
    where
        Payload: Clone + Send + Sync + 'static,
    {
        let mut bitmap = vec![false; self.state.expected_clients];
        let mut signatures = (0..self.state.expected_clients)
            .map(|_| empty_client_signature(&aggregate_key_material.params))
            .collect::<Vec<_>>();

        for submission in submissions {
            let ciphertext = (&submission.ciphertext as &dyn Any)
                .downcast_ref::<ToySteCiphertext>()
                .ok_or(ToyBackendError::WrongPayloadType(
                    "toy MKLHTS aggregation expects ToySteCiphertext payloads",
                ))?;
            let slot = aggregate_key_material
                .client_slots
                .get(&submission.client_id)
                .copied()
                .ok_or(ToyBackendError::UnknownClient(submission.client_id))?;
            let expected_scalar = hash_bytes_to_hints_field(&ciphertext.transcript_bytes);
            if expected_scalar != submission.signature.message_scalar {
                return Err(ToyBackendError::VerificationFailed(
                    "submission signature scalar does not match ciphertext transcript",
                ));
            }
            bitmap[slot] = true;
            signatures[slot] = submission.signature.inner.clone();
        }

        let bitmap_field = bitmap
            .iter()
            .map(|active| HintsField::from(*active as u64))
            .collect::<Vec<_>>();
        let proof = prove(
            &aggregate_key_material.params,
            &aggregate_key_material.prover,
            &aggregate_key_material.cache,
            &aggregate_key_material.weights,
            &bitmap_field,
            &signatures,
        );

        Ok((
            ToyAggregateSignature { proof },
            ToyVerificationMaterial { bitmap },
        ))
    }

    fn verify_aggregate_signature<Payload>(
        &self,
        _round_id: RoundId,
        aggregate_key_material: &Self::AggregateKeyMaterial,
        bundle: &ServerAggregateBundle<Payload, Self::AggregateSignature, Self::VerificationMaterial>,
    ) -> Result<(), Self::Error>
    where
        Payload: Clone + Send + Sync + 'static,
    {
        let mut expected_bitmap = vec![false; self.state.expected_clients];
        for client_id in &bundle.included_clients {
            let slot = aggregate_key_material
                .client_slots
                .get(client_id)
                .copied()
                .ok_or(ToyBackendError::UnknownClient(*client_id))?;
            expected_bitmap[slot] = true;
        }

        if expected_bitmap != bundle.verification_material.bitmap {
            return Err(ToyBackendError::VerificationFailed(
                "bundle bitmap does not match included client ids",
            ));
        }

        let verify_result = catch_unwind(AssertUnwindSafe(|| {
            verify_hints_proof(&aggregate_key_material.verifier, &bundle.aggregate_signature.proof);
        }));

        match verify_result {
            Ok(()) => Ok(()),
            Err(_) => Err(ToyBackendError::VerificationFailed(
                "hints proof verification panicked",
            )),
        }
    }
}

fn mix_seed(base_seed: u64, round_id: RoundId, nonce: u64) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(base_seed.to_le_bytes());
    hasher.update(round_id.to_le_bytes());
    hasher.update(nonce.to_le_bytes());
    let digest = hasher.finalize();
    let mut seed_bytes = [0u8; 8];
    seed_bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(seed_bytes)
}

fn hash_bytes_to_hints_field(bytes: &[u8]) -> HintsField {
    let digest = Sha256::digest(bytes);
    let mut reduced = [0u8; 8];
    reduced.copy_from_slice(&digest[..8]);
    HintsField::from(u64::from_le_bytes(reduced))
}

fn serialize_ste<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>, ToyBackendError> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .map_err(|_| ToyBackendError::Serialization("canonical serialization failed"))?;
    Ok(bytes)
}

impl Debug for ToyCommitteeEncryptionKeyRegistration {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToyCommitteeEncryptionKeyRegistration")
            .field("committee_member_id", &self.committee_member_id)
            .field("position", &self.position)
            .finish()
    }
}

impl Debug for ToySteAggregateKeyMaterial {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToySteAggregateKeyMaterial")
            .field("committee_positions", &self.committee_positions)
            .field("threshold", &self.threshold)
            .field("max_discrete_log", &self.max_discrete_log)
            .finish()
    }
}

impl Debug for ToyMklhtsAggregateKeyMaterial {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToyMklhtsAggregateKeyMaterial")
            .field("weights_len", &self.weights.len())
            .field("client_slots", &self.client_slots)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProtocolConfig, RoundConfig};

    #[test]
    fn successful_toy_round_end_to_end() {
        let protocol = ProtocolConfig {
            registration_epoch: 7,
            threshold: 2,
            expected_clients: 3,
            committee_size: 4,
        };
        let round = RoundConfig {
            round_id: 11,
            threshold: 2,
            expected_clients: 3,
            expected_committee_members: 4,
        };

        let ste = ToySteBackend::new(ToySteConfig {
            committee_size: 4,
            slot_count: 2,
            threshold: 2,
            seed: 99,
            max_discrete_log: 32,
        })
        .unwrap();
        let mklhts = ToyMklhtsBackend::new(ToyMklhtsConfig {
            expected_clients: 3,
            seed: 1234,
        })
        .unwrap();

        let simulator = SingleProcessSimulator::new(protocol, ste, mklhts);
        let clients = vec![Client::new(0), Client::new(1), Client::new(2)];
        let committee = vec![
            CommitteeMember::new(0),
            CommitteeMember::new(1),
            CommitteeMember::new(2),
            CommitteeMember::new(3),
        ];

        let offline = simulator.prepare_offline_phase(&clients, &committee).unwrap();
        let inputs = vec![
            (clients[0].clone(), ToyPlaintext::new(vec![1, 3])),
            (clients[1].clone(), ToyPlaintext::new(vec![2, 4])),
            (clients[2].clone(), ToyPlaintext::new(vec![3, 5])),
        ];

        let online = simulator
            .simulate_online_round(&round, &offline, &inputs, &committee[..2])
            .unwrap();

        assert_eq!(online.result.aggregate_plaintext, ToyPlaintext::new(vec![6, 12]));
        assert_eq!(online.result.included_clients, vec![0, 1, 2]);
        assert_eq!(offline.transcript.events.len(), 4);
        assert_eq!(online.transcript.events.len(), 5);
    }
}
