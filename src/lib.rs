pub mod crypto;
pub mod error;

#[cfg(feature = "client")]
pub mod client;

pub use error::{Result, SdkError};

pub use crypto::{
    accept_initial_session, add_participant_from_existing, create_group_call,
    create_initial_session, create_sender_key_state, decrypt_aes_gcm, decrypt_data,
    decrypt_from_sender, decrypt_group_call_audio, decrypt_group_call_video, decrypt_group_message,
    decrypt_keys, decrypt_keys_with_recovery, decrypt_with_channel_key,
    distribute_sender_key_to_participant, encrypt_aes_gcm, encrypt_data, encrypt_for_recipient,
    encrypt_group_call_audio, encrypt_group_call_video, encrypt_group_message,
    encrypt_keys_with_recovery, encrypt_with_channel_key, generate_and_encrypt_keys,
    generate_channel_key, generate_conversation_key, generate_one_time_prekeys,
    generate_recovery_key, generate_safety_number, generate_signed_prekey_from_secret,
    handle_key_rotation, handle_participant_join, handle_participant_leave,
    handle_sender_key_distribution, hash_password, join_group_call, leave_group_call,
    re_encrypt_keys_for_new_password, rotate_sender_key, update_sender_key_state_after_decrypt,
    verify_password, Argon2Config, DecryptedKeys, DsaKeyPair, EncryptResult, EncryptedKeys,
    EncryptedMessage, GroupCallAnnounce, GroupCallId, GroupCallJoin, GroupCallKeyRotation,
    GroupCallLeave, GroupCallMediaFrame, GroupCallParticipant, GroupCallParticipantState,
    GroupCallRecvSenderKey, GroupCallSenderKey, GroupCallSenderKeyDistribution,
    GroupCallSenderKeyState, GroupCallState, GroupMessage, MediaType, MessageHeader, OneTimePrekey,
    ParticipantId, RatchetState, RecoveryKeyData, SenderKeyState, SignedPrekey,
    MAX_GROUP_CALL_PARTICIPANTS,
};

#[cfg(feature = "client")]
pub use client::{ApiClient, WebSocketClient};
