pub mod call;
pub mod group;
pub mod group_call;
pub mod kem;
pub mod keys;
pub mod prekeys;
pub mod ratchet;
pub mod recovery;
pub mod safety;
pub mod symmetric;

pub use keys::{
    decrypt_keys, generate_and_encrypt_keys, generate_dsa_keypair, generate_kem_keypair,
    DecryptedKeys, DsaKeyPair, EncryptedKeys,
};

pub use kem::{
    decapsulate, decrypt_data, decrypt_from_sender, decrypt_with_channel_key, encapsulate,
    encrypt_data, encrypt_for_recipient, encrypt_with_channel_key, generate_channel_key,
    generate_conversation_key, KEM_CIPHERTEXT_SIZE, KEM_PUBLIC_KEY_SIZE, KEM_SECRET_KEY_SIZE,
};

pub use prekeys::{
    generate_one_time_prekeys, generate_signed_prekey_from_secret, verify_signed_prekey,
    OneTimePrekey, SignedPrekey,
};

pub use ratchet::{
    accept_initial_session, create_initial_session, EncryptResult, EncryptedMessage, MessageHeader,
    RatchetState,
};

pub use group::{
    create_sender_key_state, decrypt_group_message, encrypt_group_message,
    update_sender_key_state_after_decrypt, GroupMessage, SenderKeyState,
};

pub use recovery::{
    decrypt_keys_with_recovery, encrypt_keys_with_recovery, generate_recovery_key,
    re_encrypt_keys_for_new_password, RecoveryKeyData,
};

pub use safety::generate_safety_number;

pub use symmetric::{
    decrypt_aes_gcm, encrypt_aes_gcm, generate_random_bytes, hash_password, verify_password,
    Argon2Config, AES_KEY_SIZE, AES_NONCE_SIZE, ARGON2_SALT_SIZE,
};

pub use group_call::{
    add_participant_from_existing, create_group_call, decrypt_group_call_audio,
    decrypt_group_call_video, distribute_sender_key_to_participant, encrypt_group_call_audio,
    encrypt_group_call_video, handle_key_rotation, handle_participant_join,
    handle_participant_leave, handle_sender_key_distribution, join_group_call, leave_group_call,
    rotate_sender_key, GroupCallAnnounce, GroupCallId, GroupCallJoin, GroupCallKeyRotation,
    GroupCallLeave, GroupCallMediaFrame, GroupCallParticipant, GroupCallParticipantState,
    GroupCallRecvSenderKey, GroupCallSenderKey, GroupCallSenderKeyDistribution,
    GroupCallSenderKeyState, GroupCallState, MediaType, ParticipantId, MAX_GROUP_CALL_PARTICIPANTS,
};
