use std::collections::HashMap;

use super::call::CallKeyPair;
use super::keys::{GroupCallSenderKey, GroupCallSenderKeyState};
use super::participant::GroupCallParticipantState;
use super::types::{GroupCallId, ParticipantId, MAX_GROUP_CALL_PARTICIPANTS};

pub struct GroupCallState {
    pub(crate) call_id: GroupCallId,
    pub(crate) our_participant_id: ParticipantId,
    pub(crate) our_sender_key_state: GroupCallSenderKeyState,
    pub(crate) our_ephemeral_keypair: CallKeyPair,
    pub(crate) our_identity_public: Vec<u8>,
    pub(crate) participants: HashMap<ParticipantId, GroupCallParticipantState>,
    pub(crate) is_initiator: bool,
}

impl GroupCallState {
    pub fn call_id(&self) -> &GroupCallId {
        &self.call_id
    }

    pub fn our_participant_id(&self) -> &ParticipantId {
        &self.our_participant_id
    }

    pub fn participants(&self) -> &HashMap<ParticipantId, GroupCallParticipantState> {
        &self.participants
    }

    pub fn participant_count(&self) -> usize {
        self.participants.len() + 1
    }

    pub fn can_add_participant(&self) -> bool {
        self.participant_count() < MAX_GROUP_CALL_PARTICIPANTS
    }

    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    pub fn our_ephemeral_public(&self) -> &[u8] {
        &self.our_ephemeral_keypair.public
    }

    pub fn our_sender_key(&self) -> GroupCallSenderKey {
        self.our_sender_key_state.to_sender_key()
    }

    pub fn our_identity_public(&self) -> &[u8] {
        &self.our_identity_public
    }
}
