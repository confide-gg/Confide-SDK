pub mod crypto;
pub mod error;

#[cfg(feature = "client")]
pub mod client;

pub use error::{Result, SdkError};

pub use crypto::{
    accept_initial_session, create_initial_session, create_sender_key_state, decrypt_aes_gcm,
    decrypt_data, decrypt_from_sender, decrypt_group_message, decrypt_keys,
    decrypt_keys_with_recovery, decrypt_with_channel_key, encrypt_aes_gcm, encrypt_data,
    encrypt_for_recipient, encrypt_group_message, encrypt_keys_with_recovery,
    encrypt_with_channel_key, generate_and_encrypt_keys, generate_channel_key,
    generate_conversation_key, generate_one_time_prekeys, generate_recovery_key,
    generate_safety_number, generate_signed_prekey_from_secret, hash_password,
    re_encrypt_keys_for_new_password, update_sender_key_state_after_decrypt, verify_password,
    Argon2Config, DecryptedKeys, DsaKeyPair, EncryptResult, EncryptedKeys, EncryptedMessage,
    GroupMessage, MessageHeader, OneTimePrekey, RatchetState, RecoveryKeyData, SenderKeyState,
    SignedPrekey,
};

#[cfg(feature = "client")]
pub use client::{ApiClient, WebSocketClient};
