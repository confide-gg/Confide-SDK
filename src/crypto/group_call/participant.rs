use serde::{Deserialize, Serialize};

use super::keys::GroupCallRecvSenderKey;
use super::types::ParticipantId;

#[derive(Clone, Serialize, Deserialize)]
pub struct GroupCallParticipant {
    pub participant_id: ParticipantId,
    pub identity_public_key: Vec<u8>,
    pub ephemeral_kem_public: Vec<u8>,
    pub joined_at: u64,
}

pub struct GroupCallParticipantState {
    pub info: GroupCallParticipant,
    pub sender_key: Option<GroupCallRecvSenderKey>,
}
