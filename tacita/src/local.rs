use std::{
    fs,
    path::{Path, PathBuf},
};

use ark_bls12_381::Bls12_381 as SteCurve;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_serialize_04::{
    CanonicalDeserialize as CanonicalDeserialize04, CanonicalSerialize as CanonicalSerialize04,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    client::Client,
    committee::CommitteeMember,
    config::LocalCliConfig,
    errors::TacitaError,
    server::Server,
    simulator::{
        SingleProcessSimulator, ToyAggregateSignature, ToyClientVerificationKey,
        ToyCommitteeEncryptionKeyRegistration, ToyMklhtsAggregateKeyMaterial, ToyMklhtsBackend,
        ToyMklhtsConfig, ToyPlaintext, ToySignature, ToySteAggregateCiphertext,
        ToySteAggregateKeyMaterial, ToySteBackend, ToySteCiphertext, ToySteConfig,
        ToyStePartialDecryptionShare, ToyVerificationMaterial, TranscriptLog,
    },
    types::{
        ClientId, ClientSigningKeyRegistration, ClientSubmission, CommitteeAggregateKeyMaterial,
        CommitteeEncryptionKeyRegistration, CommitteeMemberId, CommitteePartialDecryption,
        OpaquePayload, ServerAggregateBundle, ServerAggregateResult,
    },
};

pub type ToySimulator = SingleProcessSimulator<ToySteBackend, ToyMklhtsBackend>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredClientSigningKeyRegistration {
    pub message: ClientSigningKeyRegistration<OpaquePayload>,
}

fn ser04<T: CanonicalSerialize04>(writer: &mut Vec<u8>, value: &T) -> Result<(), TacitaError> {
    value
        .serialize_compressed(&mut *writer)
        .map_err(|_| TacitaError::InvalidState {
            message: "failed to serialize arkworks 0.4 value",
        })
}

fn de04<T: CanonicalDeserialize04>(reader: &mut &[u8]) -> Result<T, TacitaError> {
    T::deserialize_compressed(&mut *reader).map_err(|_| TacitaError::Validation {
        message: "failed to deserialize arkworks 0.4 value",
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredCommitteeEncryptionKeyRegistration {
    pub message: CommitteeEncryptionKeyRegistration<OpaquePayload>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredCommitteeAggregateKeyMaterial {
    pub message: CommitteeAggregateKeyMaterial<OpaquePayload, OpaquePayload>,
    pub client_ids: Vec<ClientId>,
    pub committee_member_ids: Vec<CommitteeMemberId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredClientSubmission {
    pub message: ClientSubmission<OpaquePayload, OpaquePayload>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredServerAggregateBundle {
    pub message: ServerAggregateBundle<OpaquePayload, OpaquePayload, OpaquePayload>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredCommitteePartialDecryption {
    pub message: CommitteePartialDecryption<OpaquePayload>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredServerAggregateResult {
    pub message: ServerAggregateResult<OpaquePayload>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredSimulationRound {
    pub offline_transcript: TranscriptLog,
    pub online_transcript: TranscriptLog,
    pub result: StoredServerAggregateResult,
}

pub fn load_config(path: &Path) -> Result<LocalCliConfig, TacitaError> {
    let contents = fs::read_to_string(path).map_err(|_| TacitaError::InvalidState {
        message: "failed to read local config file",
    })?;
    toml::from_str(&contents).map_err(|_| TacitaError::Validation {
        message: "failed to parse local config file",
    })
}

pub fn build_toy_simulator(config: &LocalCliConfig) -> Result<ToySimulator, TacitaError> {
    let ste = ToySteBackend::new(ToySteConfig {
        committee_size: config.toy_ste.committee_size,
        slot_count: config.toy_ste.slot_count,
        threshold: config.toy_ste.threshold,
        seed: config.toy_ste.seed,
        max_discrete_log: config.toy_ste.max_discrete_log,
    })
    .map_err(|err| TacitaError::primitive("ste", err))?;

    let mklhts = ToyMklhtsBackend::new(ToyMklhtsConfig {
        expected_clients: config.toy_mklhts.expected_clients,
        seed: config.toy_mklhts.seed,
    })
    .map_err(|err| TacitaError::primitive("mklhts", err))?;

    Ok(SingleProcessSimulator::new(
        config.protocol.clone(),
        ste,
        mklhts,
    ))
}

pub fn configured_clients(config: &LocalCliConfig) -> Vec<Client> {
    config
        .client_ids
        .clone()
        .unwrap_or_else(|| (0..config.protocol.expected_clients as u64).collect())
        .into_iter()
        .map(Client::new)
        .collect()
}

pub fn configured_committee(config: &LocalCliConfig) -> Vec<CommitteeMember> {
    config
        .committee_member_ids
        .clone()
        .unwrap_or_else(|| (0..config.protocol.committee_size as u64).collect())
        .into_iter()
        .map(CommitteeMember::new)
        .collect()
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), TacitaError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| TacitaError::InvalidState {
            message: "failed to create parent directory for output",
        })?;
    }
    let contents = serde_json::to_vec_pretty(value).map_err(|_| TacitaError::InvalidState {
        message: "failed to serialize json output",
    })?;
    fs::write(path, contents).map_err(|_| TacitaError::InvalidState {
        message: "failed to write json output",
    })
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, TacitaError> {
    let contents = fs::read(path).map_err(|_| TacitaError::InvalidState {
        message: "failed to read json input",
    })?;
    serde_json::from_slice(&contents).map_err(|_| TacitaError::Validation {
        message: "failed to deserialize json input",
    })
}

pub fn parse_plaintext_spec(spec: &str) -> Result<ToyPlaintext, TacitaError> {
    let slots = spec
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| {
            part.trim().parse::<u64>().map_err(|_| TacitaError::Validation {
                message: "failed to parse plaintext slot as u64",
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    if slots.is_empty() {
        return Err(TacitaError::Validation {
            message: "plaintext must contain at least one slot",
        });
    }

    Ok(ToyPlaintext::new(slots))
}

pub fn parse_round_inputs(spec: &str) -> Result<Vec<ToyPlaintext>, TacitaError> {
    spec.split(';')
        .filter(|entry| !entry.trim().is_empty())
        .map(parse_plaintext_spec)
        .collect()
}

pub fn register_client(
    config: &LocalCliConfig,
    client_id: ClientId,
) -> Result<StoredClientSigningKeyRegistration, TacitaError> {
    let simulator = build_toy_simulator(config)?;
    let client = Client::new(client_id);
    let registration = client.register_signing_key(config.protocol.registration_epoch, &simulator.mklhts)?;
    let native_key = registration.verification_key;
    let stored = ClientSigningKeyRegistration {
        registration_epoch: registration.registration_epoch,
        client_id: registration.client_id,
        verification_key: OpaquePayload {
            bytes: serialize_toy_client_verification_key(&native_key)?,
        },
    };

    Ok(StoredClientSigningKeyRegistration { message: stored })
}

pub fn register_committee_member(
    config: &LocalCliConfig,
    committee_member_id: CommitteeMemberId,
) -> Result<StoredCommitteeEncryptionKeyRegistration, TacitaError> {
    let simulator = build_toy_simulator(config)?;
    let member = CommitteeMember::new(committee_member_id);
    let registration =
        member.register_encryption_key(config.protocol.registration_epoch, &simulator.ste)?;
    let native_registration = registration.encryption_key_registration;
    let stored = CommitteeEncryptionKeyRegistration {
        registration_epoch: registration.registration_epoch,
        committee_member_id: registration.committee_member_id,
        encryption_key_registration: OpaquePayload {
            bytes: serialize_toy_committee_registration(&native_registration)?,
        },
    };

    Ok(StoredCommitteeEncryptionKeyRegistration { message: stored })
}

pub fn derive_aggregate_material(
    config: &LocalCliConfig,
    client_registration_paths: &[PathBuf],
    committee_registration_paths: &[PathBuf],
) -> Result<StoredCommitteeAggregateKeyMaterial, TacitaError> {
    let simulator = build_toy_simulator(config)?;
    let clients = client_registration_paths
        .iter()
        .map(|path| read_json::<StoredClientSigningKeyRegistration>(path))
        .collect::<Result<Vec<_>, _>>()?;
    let committee = committee_registration_paths
        .iter()
        .map(|path| read_json::<StoredCommitteeEncryptionKeyRegistration>(path))
        .collect::<Result<Vec<_>, _>>()?;

    let client_ids = clients.iter().map(|entry| entry.message.client_id).collect::<Vec<_>>();
    let committee_member_ids = committee
        .iter()
        .map(|entry| entry.message.committee_member_id)
        .collect::<Vec<_>>();

    let client_regs = client_ids
        .iter()
        .map(|client_id| Client::new(*client_id).register_signing_key(config.protocol.registration_epoch, &simulator.mklhts))
        .collect::<Result<Vec<_>, _>>()?;
    let committee_regs = committee_member_ids
        .iter()
        .map(|member_id| {
            CommitteeMember::new(*member_id)
                .register_encryption_key(config.protocol.registration_epoch, &simulator.ste)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let aggregate_key_material =
        simulator.derive_committee_aggregate_key_material(&client_regs, &committee_regs)?;

    Ok(StoredCommitteeAggregateKeyMaterial {
        message: CommitteeAggregateKeyMaterial {
            registration_epoch: aggregate_key_material.registration_epoch,
            threshold: aggregate_key_material.threshold,
            committee_encryption_material: OpaquePayload {
                bytes: b"deterministic-toy-ste-material".to_vec(),
            },
            client_verification_material: OpaquePayload {
                bytes: b"deterministic-toy-mklhts-material".to_vec(),
            },
        },
        client_ids,
        committee_member_ids,
    })
}

pub fn load_native_aggregate_material(
    config: &LocalCliConfig,
    stored: &StoredCommitteeAggregateKeyMaterial,
) -> Result<
    CommitteeAggregateKeyMaterial<ToySteAggregateKeyMaterial, ToyMklhtsAggregateKeyMaterial>,
    TacitaError,
> {
    let simulator = build_toy_simulator(config)?;
    let client_regs = stored
        .client_ids
        .iter()
        .map(|client_id| Client::new(*client_id).register_signing_key(stored.message.registration_epoch, &simulator.mklhts))
        .collect::<Result<Vec<_>, _>>()?;
    let committee_regs = stored
        .committee_member_ids
        .iter()
        .map(|member_id| {
            CommitteeMember::new(*member_id)
                .register_encryption_key(stored.message.registration_epoch, &simulator.ste)
        })
        .collect::<Result<Vec<_>, _>>()?;
    simulator.derive_committee_aggregate_key_material(&client_regs, &committee_regs)
}

pub fn submit_client_input(
    config: &LocalCliConfig,
    aggregate_material_path: &Path,
    client_id: ClientId,
    plaintext: &ToyPlaintext,
) -> Result<StoredClientSubmission, TacitaError> {
    let simulator = build_toy_simulator(config)?;
    let stored_aggregate = read_json::<StoredCommitteeAggregateKeyMaterial>(aggregate_material_path)?;
    let aggregate_key_material = load_native_aggregate_material(config, &stored_aggregate)?;
    let submission = Client::new(client_id).submit(
        &config.round,
        &aggregate_key_material,
        plaintext,
        &simulator.ste,
        &simulator.mklhts,
    )?;

    Ok(StoredClientSubmission {
        message: ClientSubmission {
            round_id: submission.round_id,
            client_id: submission.client_id,
            ciphertext: OpaquePayload {
                bytes: serialize_ste_ciphertext(&submission.ciphertext)?,
            },
            signature: OpaquePayload {
                bytes: serialize_toy_signature(&submission.signature)?,
            },
        },
    })
}

pub fn aggregate_submissions(
    config: &LocalCliConfig,
    aggregate_material_path: &Path,
    submission_paths: &[PathBuf],
) -> Result<StoredServerAggregateBundle, TacitaError> {
    let simulator = build_toy_simulator(config)?;
    let server = Server::new();
    let stored_aggregate = read_json::<StoredCommitteeAggregateKeyMaterial>(aggregate_material_path)?;
    let aggregate_key_material = load_native_aggregate_material(config, &stored_aggregate)?;
    let submissions = submission_paths
        .iter()
        .map(|path| read_json::<StoredClientSubmission>(path))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(stored_submission_to_native)
        .collect::<Result<Vec<_>, _>>()?;

    let bundle = server.aggregate_submissions(
        &config.round,
        &aggregate_key_material,
        &submissions,
        &simulator.ste,
        &simulator.mklhts,
    )?;

    Ok(StoredServerAggregateBundle {
        message: ServerAggregateBundle {
            round_id: bundle.round_id,
            included_clients: bundle.included_clients.clone(),
            aggregate_ciphertext: OpaquePayload {
                bytes: serialize_aggregate_ciphertext(&bundle.aggregate_ciphertext)?,
            },
            aggregate_signature: OpaquePayload {
                bytes: serialize_toy_aggregate_signature(&bundle.aggregate_signature)?,
            },
            verification_material: OpaquePayload {
                bytes: bincode::serialize(&bundle.verification_material).map_err(|_| {
                    TacitaError::InvalidState {
                        message: "failed to serialize verification material",
                    }
                })?,
            },
        },
    })
}

pub fn partial_decrypt_bundle(
    config: &LocalCliConfig,
    aggregate_material_path: &Path,
    bundle_path: &Path,
    committee_member_id: CommitteeMemberId,
) -> Result<StoredCommitteePartialDecryption, TacitaError> {
    let simulator = build_toy_simulator(config)?;
    let stored_aggregate = read_json::<StoredCommitteeAggregateKeyMaterial>(aggregate_material_path)?;
    let aggregate_key_material = load_native_aggregate_material(config, &stored_aggregate)?;
    let bundle = stored_bundle_to_native(&read_json::<StoredServerAggregateBundle>(bundle_path)?)?;
    let partial = CommitteeMember::new(committee_member_id).verify_and_partial_decrypt(
        &config.round,
        &aggregate_key_material,
        &bundle,
        &simulator.ste,
        &simulator.mklhts,
    )?;

    Ok(StoredCommitteePartialDecryption {
        message: CommitteePartialDecryption {
            round_id: partial.round_id,
            committee_member_id: partial.committee_member_id,
            partial_decryption_share: OpaquePayload {
                bytes: serialize_partial_decryption_share(&partial.partial_decryption_share)?,
            },
        },
    })
}

pub fn finalize_aggregate_result(
    config: &LocalCliConfig,
    aggregate_material_path: &Path,
    bundle_path: &Path,
    partial_paths: &[PathBuf],
) -> Result<StoredServerAggregateResult, TacitaError> {
    let simulator = build_toy_simulator(config)?;
    let server = Server::new();
    let stored_aggregate = read_json::<StoredCommitteeAggregateKeyMaterial>(aggregate_material_path)?;
    let aggregate_key_material = load_native_aggregate_material(config, &stored_aggregate)?;
    let bundle = stored_bundle_to_native(&read_json::<StoredServerAggregateBundle>(bundle_path)?)?;
    let partials = partial_paths
        .iter()
        .map(|path| read_json::<StoredCommitteePartialDecryption>(path))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(stored_partial_to_native)
        .collect::<Result<Vec<_>, _>>()?;

    let result = server.finalize_result::<ToySteBackend, ToyMklhtsBackend>(
        &config.round,
        &aggregate_key_material,
        &bundle,
        &partials,
        &simulator.ste,
    )?;

    Ok(StoredServerAggregateResult {
        message: ServerAggregateResult {
            round_id: result.round_id,
            included_clients: result.included_clients,
            aggregate_plaintext: OpaquePayload {
                bytes: bincode::serialize(&result.aggregate_plaintext).map_err(|_| {
                    TacitaError::InvalidState {
                        message: "failed to serialize aggregate plaintext",
                    }
                })?,
            },
        },
    })
}

pub fn run_simulation_round(
    config: &LocalCliConfig,
    inputs: &[ToyPlaintext],
) -> Result<StoredSimulationRound, TacitaError> {
    let simulator = build_toy_simulator(config)?;
    let clients = configured_clients(config);
    let committee = configured_committee(config);
    let offline = simulator.prepare_offline_phase(&clients, &committee)?;
    let online_inputs = clients
        .iter()
        .cloned()
        .zip(inputs.iter().cloned())
        .collect::<Vec<_>>();
    let online = simulator.simulate_online_round(
        &config.round,
        &offline,
        &online_inputs,
        &committee[..config.round.threshold],
    )?;

    Ok(StoredSimulationRound {
        offline_transcript: offline.transcript,
        online_transcript: online.transcript,
        result: StoredServerAggregateResult {
            message: ServerAggregateResult {
                round_id: online.result.round_id,
                included_clients: online.result.included_clients,
                aggregate_plaintext: OpaquePayload {
                    bytes: bincode::serialize(&online.result.aggregate_plaintext).map_err(|_| {
                        TacitaError::InvalidState {
                            message: "failed to serialize simulator result",
                        }
                    })?,
                },
            },
        },
    })
}

pub fn decode_stored_result(
    stored: &StoredServerAggregateResult,
) -> Result<ToyPlaintext, TacitaError> {
    bincode::deserialize(&stored.message.aggregate_plaintext.bytes).map_err(|_| {
        TacitaError::Validation {
            message: "failed to decode stored aggregate plaintext",
        }
    })
}

fn stored_submission_to_native(
    stored: StoredClientSubmission,
) -> Result<ClientSubmission<ToySteCiphertext, ToySignature>, TacitaError> {
    Ok(ClientSubmission {
        round_id: stored.message.round_id,
        client_id: stored.message.client_id,
        ciphertext: deserialize_ste_ciphertext(&stored.message.ciphertext.bytes)?,
        signature: deserialize_toy_signature(&stored.message.signature.bytes)?,
    })
}

fn stored_bundle_to_native(
    stored: &StoredServerAggregateBundle,
) -> Result<
    ServerAggregateBundle<ToySteAggregateCiphertext, ToyAggregateSignature, ToyVerificationMaterial>,
    TacitaError,
> {
    Ok(ServerAggregateBundle {
        round_id: stored.message.round_id,
        included_clients: stored.message.included_clients.clone(),
        aggregate_ciphertext: deserialize_aggregate_ciphertext(&stored.message.aggregate_ciphertext.bytes)?,
        aggregate_signature: deserialize_toy_aggregate_signature(&stored.message.aggregate_signature.bytes)?,
        verification_material: bincode::deserialize(&stored.message.verification_material.bytes)
            .map_err(|_| TacitaError::Validation {
                message: "failed to decode verification material",
            })?,
    })
}

fn stored_partial_to_native(
    stored: StoredCommitteePartialDecryption,
) -> Result<CommitteePartialDecryption<ToyStePartialDecryptionShare>, TacitaError> {
    Ok(CommitteePartialDecryption {
        round_id: stored.message.round_id,
        committee_member_id: stored.message.committee_member_id,
        partial_decryption_share: deserialize_partial_decryption_share(
            &stored.message.partial_decryption_share.bytes,
        )?,
    })
}

fn serialize_toy_client_verification_key(
    value: &ToyClientVerificationKey,
) -> Result<Vec<u8>, TacitaError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&value.client_id.to_le_bytes());
    bytes.extend_from_slice(&(value.slot as u64).to_le_bytes());
    value
        .public_key
        .serialize_compressed(&mut bytes)
        .map_err(|_| TacitaError::InvalidState {
            message: "failed to serialize client verification key",
        })?;
    Ok(bytes)
}

fn serialize_toy_committee_registration(
    value: &ToyCommitteeEncryptionKeyRegistration,
) -> Result<Vec<u8>, TacitaError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&value.committee_member_id.to_le_bytes());
    bytes.extend_from_slice(&(value.position as u64).to_le_bytes());
    value
        .lag_public_key
        .serialize_compressed(&mut bytes)
        .map_err(|_| TacitaError::InvalidState {
            message: "failed to serialize committee registration",
        })?;
    Ok(bytes)
}

fn serialize_ste_ciphertext(value: &ToySteCiphertext) -> Result<Vec<u8>, TacitaError> {
    let mut bytes = Vec::new();
    value
        .inner
        .serialize_compressed(&mut bytes)
        .map_err(|_| TacitaError::InvalidState {
            message: "failed to serialize ste ciphertext",
        })?;
    Ok(bytes)
}

fn deserialize_ste_ciphertext(bytes: &[u8]) -> Result<ToySteCiphertext, TacitaError> {
    let inner = ste::encryption::Ciphertext::<SteCurve>::deserialize_compressed(bytes).map_err(|_| {
        TacitaError::Validation {
            message: "failed to deserialize ste ciphertext",
        }
    })?;
    let transcript_bytes = serialize_ste(&inner)?;
    Ok(ToySteCiphertext {
        inner,
        slot_count: transcript_slot_count(&transcript_bytes)?,
        transcript_bytes,
    })
}

fn serialize_aggregate_ciphertext(value: &ToySteAggregateCiphertext) -> Result<Vec<u8>, TacitaError> {
    let mut bytes = Vec::new();
    value
        .inner
        .serialize_compressed(&mut bytes)
        .map_err(|_| TacitaError::InvalidState {
            message: "failed to serialize aggregate ciphertext",
        })?;
    Ok(bytes)
}

fn deserialize_aggregate_ciphertext(bytes: &[u8]) -> Result<ToySteAggregateCiphertext, TacitaError> {
    let inner = ste::encryption::Ciphertext::<SteCurve>::deserialize_compressed(bytes).map_err(|_| {
        TacitaError::Validation {
            message: "failed to deserialize aggregate ciphertext",
        }
    })?;
    let transcript_bytes = serialize_ste(&inner)?;
    Ok(ToySteAggregateCiphertext {
        contributor_count: 0,
        slot_count: transcript_slot_count(&transcript_bytes)?,
        inner,
        transcript_bytes,
    })
}

fn serialize_partial_decryption_share(
    value: &ToyStePartialDecryptionShare,
) -> Result<Vec<u8>, TacitaError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(value.inner.id as u64).to_le_bytes());
    value
        .inner
        .pd
        .serialize_compressed(&mut bytes)
        .map_err(|_| TacitaError::InvalidState {
            message: "failed to serialize partial decryption share",
        })?;
    Ok(bytes)
}

fn deserialize_partial_decryption_share(
    bytes: &[u8],
) -> Result<ToyStePartialDecryptionShare, TacitaError> {
    if bytes.len() < 8 {
        return Err(TacitaError::Validation {
            message: "partial decryption share file is too short",
        });
    }
    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&bytes[..8]);
    let id = u64::from_le_bytes(id_bytes) as usize;
    let mut reader = &bytes[8..];
    let pd = <SteCurve as ark_ec::pairing::Pairing>::G1::deserialize_compressed(&mut reader)
        .map_err(|_| TacitaError::Validation {
            message: "failed to deserialize partial decryption share",
        })?;
    let inner = ste::partial_decryption::PartialDecryption { id, pd };
    Ok(ToyStePartialDecryptionShare { inner })
}

fn serialize_toy_signature(value: &ToySignature) -> Result<Vec<u8>, TacitaError> {
    let mut bytes = Vec::new();
    value
        .message_scalar
        .serialize_compressed(&mut bytes)
        .map_err(|_| TacitaError::InvalidState {
            message: "failed to serialize mklhts message scalar",
        })?;
    serialize_hints_signature(&value.inner, &mut bytes)?;
    Ok(bytes)
}

fn deserialize_toy_signature(bytes: &[u8]) -> Result<ToySignature, TacitaError> {
    let mut reader = bytes;
    let message_scalar =
        hints::types::F::deserialize_compressed(&mut reader).map_err(|_| TacitaError::Validation {
            message: "failed to deserialize mklhts message scalar",
        })?;
    let inner = deserialize_hints_signature(&mut reader)?;
    Ok(ToySignature {
        inner,
        message_scalar,
    })
}

fn serialize_toy_aggregate_signature(value: &ToyAggregateSignature) -> Result<Vec<u8>, TacitaError> {
    let mut bytes = Vec::new();
    serialize_hints_proof(&value.proof, &mut bytes)?;
    Ok(bytes)
}

fn deserialize_toy_aggregate_signature(bytes: &[u8]) -> Result<ToyAggregateSignature, TacitaError> {
    let mut reader = bytes;
    let proof = deserialize_hints_proof(&mut reader)?;
    Ok(ToyAggregateSignature { proof })
}

fn serialize_hints_signature(
    value: &hints::types::ClientSignature,
    writer: &mut Vec<u8>,
) -> Result<(), TacitaError> {
    ser04(writer, &value.message_commitment)?;
    ser04(writer, &value.signature)?;
    ser04(writer, &value.shint.pk_times_message)?;
    ser04(writer, &value.shint.sk_l_i_commitment_times_message)?;
    ser04(writer, &value.shint.q1_sum_times_message)?;
    ser04(writer, &value.shint.q2_commitment_times_message)?;
    ser04(writer, &value.skshint.q1_commitment_times_message)?;
    ser04(writer, &value.skshint.q2_commitment_times_message)
}

fn deserialize_hints_signature(
    reader: &mut &[u8],
) -> Result<hints::types::ClientSignature, TacitaError> {
    Ok(hints::types::ClientSignature {
        message_commitment: de04(reader)?,
        signature: de04(reader)?,
        shint: hints::types::SHint {
            pk_times_message: de04(reader)?,
            sk_l_i_commitment_times_message: de04(reader)?,
            q1_sum_times_message: de04(reader)?,
            q2_commitment_times_message: de04(reader)?,
        },
        skshint: hints::types::SkSHint {
            q1_commitment_times_message: de04(reader)?,
            q2_commitment_times_message: de04(reader)?,
        },
    })
}

fn serialize_hints_proof(
    value: &hints::types::Proof,
    writer: &mut Vec<u8>,
) -> Result<(), TacitaError> {
    ser04(writer, &value.agg_pk)?;
    ser04(writer, &value.agg_weight)?;
    ser04(writer, &value.r)?;
    ser04(writer, &value.merged_proof)?;
    ser04(writer, &value.psw_of_r)?;
    ser04(writer, &value.psw_of_r_div_omega)?;
    ser04(writer, &value.psw_of_r_div_omega_proof)?;
    ser04(writer, &value.w_of_r)?;
    ser04(writer, &value.b_of_r)?;
    ser04(writer, &value.psw_wff_q_of_r)?;
    ser04(writer, &value.psw_check_q_of_r)?;
    ser04(writer, &value.b_wff_q_of_r)?;
    ser04(writer, &value.b_check_q_of_r)?;
    ser04(writer, &value.psw_of_x_com)?;
    ser04(writer, &value.b_of_x_com)?;
    ser04(writer, &value.psw_wff_q_of_x_com)?;
    ser04(writer, &value.psw_check_q_of_x_com)?;
    ser04(writer, &value.b_wff_q_of_x_com)?;
    ser04(writer, &value.b_check_q_of_x_com)?;
    ser04(writer, &value.aggregate_material.sk_q1_com)?;
    ser04(writer, &value.aggregate_material.sk_q2_com)?;
    ser04(writer, &value.aggregate_material.s_q1_com)?;
    ser04(writer, &value.aggregate_material.s_q2_com)?;
    ser04(writer, &value.aggregate_material.sk_s_q1_com)?;
    ser04(writer, &value.aggregate_material.sk_s_q2_com)
}

fn deserialize_hints_proof(reader: &mut &[u8]) -> Result<hints::types::Proof, TacitaError> {
    Ok(hints::types::Proof {
        agg_pk: de04(reader)?,
        agg_weight: de04(reader)?,
        r: de04(reader)?,
        merged_proof: de04(reader)?,
        psw_of_r: de04(reader)?,
        psw_of_r_div_omega: de04(reader)?,
        psw_of_r_div_omega_proof: de04(reader)?,
        w_of_r: de04(reader)?,
        b_of_r: de04(reader)?,
        psw_wff_q_of_r: de04(reader)?,
        psw_check_q_of_r: de04(reader)?,
        b_wff_q_of_r: de04(reader)?,
        b_check_q_of_r: de04(reader)?,
        psw_of_x_com: de04(reader)?,
        b_of_x_com: de04(reader)?,
        psw_wff_q_of_x_com: de04(reader)?,
        psw_check_q_of_x_com: de04(reader)?,
        b_wff_q_of_x_com: de04(reader)?,
        b_check_q_of_x_com: de04(reader)?,
        aggregate_material: hints::types::AggregateProofMaterial {
            sk_q1_com: de04(reader)?,
            sk_q2_com: de04(reader)?,
            s_q1_com: de04(reader)?,
            s_q2_com: de04(reader)?,
            sk_s_q1_com: de04(reader)?,
            sk_s_q2_com: de04(reader)?,
        },
    })
}

fn serialize_ste<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>, TacitaError> {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes).map_err(|_| TacitaError::InvalidState {
        message: "failed to serialize ark value",
    })?;
    Ok(bytes)
}

fn transcript_slot_count(bytes: &[u8]) -> Result<usize, TacitaError> {
    let inner =
        ste::encryption::Ciphertext::<SteCurve>::deserialize_compressed(bytes).map_err(|_| {
            TacitaError::Validation {
                message: "failed to inspect ciphertext transcript",
            }
        })?;
    Ok(inner.ct.len())
}
