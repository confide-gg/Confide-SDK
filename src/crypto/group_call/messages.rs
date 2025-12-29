use serde::{Deserialize, Serialize};

use super::types::{GroupCallId, MediaType, ParticipantId};

#[derive(Clone, Serialize, Deserialize)]
pub struct GroupCallAnnounce {
    pub call_id: GroupCallId,
    pub initiator_id: ParticipantId,
    pub initiator_identity_public: Vec<u8>,
    pub ephemeral_kem_public: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GroupCallJoin {
    pub call_id: GroupCallId,
    pub participant_id: ParticipantId,
    pub participant_identity_public: Vec<u8>,
    pub ephemeral_kem_public: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GroupCallSenderKeyDistribution {
    pub call_id: GroupCallId,
    pub from_participant: ParticipantId,
    pub to_participant: ParticipantId,
    pub kem_ciphertext: Vec<u8>,
    pub encrypted_sender_key: Vec<u8>,
    pub key_id: u32,
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GroupCallLeave {
    pub call_id: GroupCallId,
    pub participant_id: ParticipantId,
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GroupCallKeyRotation {
    pub call_id: GroupCallId,
    pub participant_id: ParticipantId,
    pub new_key_id: u32,
    pub distributions: Vec<GroupCallSenderKeyDistribution>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GroupCallMediaFrame {
    pub sender_id: ParticipantId,
    pub key_id: u32,
    pub media_type: MediaType,
    pub nonce_counter: u64,
    pub ciphertext: Vec<u8>,
}
