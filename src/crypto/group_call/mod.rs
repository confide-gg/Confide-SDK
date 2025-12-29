mod crypto;
mod keys;
mod media;
mod messages;
mod operations;
mod participant;
mod state;
mod types;

#[cfg(test)]
mod tests;

use super::call;
use super::symmetric;

pub use keys::{GroupCallRecvSenderKey, GroupCallSenderKey, GroupCallSenderKeyState};
pub use media::{
    decrypt_group_call_audio, decrypt_group_call_screenshare, decrypt_group_call_video,
    encrypt_group_call_audio, encrypt_group_call_screenshare, encrypt_group_call_video,
};
pub use messages::{
    GroupCallAnnounce, GroupCallJoin, GroupCallKeyRotation, GroupCallLeave, GroupCallMediaFrame,
    GroupCallSenderKeyDistribution,
};
pub use operations::{
    add_participant_from_existing, create_group_call, distribute_sender_key_to_participant,
    handle_key_rotation, handle_participant_join, handle_participant_leave,
    handle_sender_key_distribution, join_group_call, leave_group_call, rotate_sender_key,
};
pub use participant::{GroupCallParticipant, GroupCallParticipantState};
pub use state::GroupCallState;
pub use types::{
    GroupCallId, MediaType, ParticipantId, GROUP_CALL_ID_SIZE, MAX_GROUP_CALL_PARTICIPANTS,
    PARTICIPANT_ID_SIZE,
};
