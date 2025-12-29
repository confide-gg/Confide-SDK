use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

use super::keys::CallMediaKeys;
use super::symmetric::hkdf_expand;
use crate::error::{Result, SdkError};

pub fn encrypt_with_nonce(key: &[u8], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SdkError::Encryption(format!("Failed to create cipher: {}", e)))?;

    cipher
        .encrypt(&Nonce::from(*nonce), plaintext)
        .map_err(|e| SdkError::Encryption(format!("AES-GCM encryption failed: {}", e)))
}

pub fn decrypt_with_nonce(key: &[u8], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SdkError::Decryption(format!("Failed to create cipher: {}", e)))?;

    cipher
        .decrypt(&Nonce::from(*nonce), ciphertext)
        .map_err(|e| SdkError::Decryption(format!("AES-GCM decryption failed: {}", e)))
}

pub fn derive_media_keys(shared_secret_1: &[u8; 32], shared_secret_2: &[u8; 32]) -> CallMediaKeys {
    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(shared_secret_1);
    combined.extend_from_slice(shared_secret_2);

    let caller_send_key = hkdf_expand(&combined, b"confide_call_caller_send", 32);
    let callee_send_key = hkdf_expand(&combined, b"confide_call_callee_send", 32);

    let mut send_key = [0u8; 32];
    let mut recv_key = [0u8; 32];

    send_key.copy_from_slice(&caller_send_key);
    recv_key.copy_from_slice(&callee_send_key);

    CallMediaKeys { send_key, recv_key }
}
