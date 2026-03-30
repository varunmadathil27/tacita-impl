use serde::{Deserialize, Serialize};

use crate::types::{RegistrationEpoch, RoundId};
use crate::types::{ClientId, CommitteeMemberId};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolConfig {
    pub registration_epoch: RegistrationEpoch,
    pub threshold: usize,
    pub expected_clients: usize,
    pub committee_size: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundConfig {
    pub round_id: RoundId,
    pub threshold: usize,
    pub expected_clients: usize,
    pub expected_committee_members: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToySteBackendConfig {
    pub committee_size: usize,
    pub slot_count: usize,
    pub threshold: usize,
    pub seed: u64,
    pub max_discrete_log: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToyMklhtsBackendConfig {
    pub expected_clients: usize,
    pub seed: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalCliConfig {
    pub protocol: ProtocolConfig,
    pub round: RoundConfig,
    pub toy_ste: ToySteBackendConfig,
    pub toy_mklhts: ToyMklhtsBackendConfig,
    pub client_ids: Option<Vec<ClientId>>,
    pub committee_member_ids: Option<Vec<CommitteeMemberId>>,
}
