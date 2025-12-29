use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

use super::symmetric::generate_random_bytes;
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

pub fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce_bytes = generate_random_bytes(12);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SdkError::Encryption(format!("Failed to create cipher: {}", e)))?;

    let ciphertext = cipher
        .encrypt(&Nonce::from(nonce), plaintext)
        .map_err(|e| SdkError::Encryption(format!("AES-GCM encryption failed: {}", e)))?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub fn decrypt_with_key(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(SdkError::Decryption("Data too short".to_string()));
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SdkError::Decryption(format!("Failed to create cipher: {}", e)))?;

    cipher
        .decrypt(&Nonce::from(nonce), ciphertext)
        .map_err(|e| SdkError::Decryption(format!("AES-GCM decryption failed: {}", e)))
}
