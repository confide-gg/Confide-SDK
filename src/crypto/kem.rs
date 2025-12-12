use std::ops::Deref;

use rand::rngs::OsRng;
use rustpq::ml_kem_hybrid::p384_mlkem1024::{self, Ciphertext, PublicKey, SecretKey};

use super::symmetric::{
    decrypt_aes_gcm, encrypt_aes_gcm, generate_random_bytes, hkdf_expand_to_key, AES_KEY_SIZE,
};
use crate::error::{Result, SdkError};

pub const KEM_PUBLIC_KEY_SIZE: usize = 1665;
pub const KEM_SECRET_KEY_SIZE: usize = 3216;
pub const KEM_CIPHERTEXT_SIZE: usize = 1665;

pub fn generate_conversation_key() -> Vec<u8> {
    generate_random_bytes(AES_KEY_SIZE)
}

pub fn generate_channel_key() -> Vec<u8> {
    generate_random_bytes(AES_KEY_SIZE)
}

pub fn encrypt_for_recipient(recipient_public_key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let pk = PublicKey::from_bytes(recipient_public_key)
        .map_err(|_| SdkError::Kem("Invalid recipient public key".to_string()))?;

    let (ciphertext, shared_secret) = p384_mlkem1024::encapsulate(&pk, &mut OsRng);

    let encryption_key = shared_secret.derive_key();

    let encrypted_data = encrypt_aes_gcm(&encryption_key, data)?;

    let mut result = Vec::with_capacity(KEM_CIPHERTEXT_SIZE + encrypted_data.len());
    let ct_bytes = ciphertext.as_bytes();
    result.extend_from_slice(&ct_bytes);
    result.extend_from_slice(&encrypted_data);

    Ok(result)
}

pub fn decrypt_from_sender(secret_key: &[u8], encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < KEM_CIPHERTEXT_SIZE {
        return Err(SdkError::InvalidCiphertext);
    }

    let sk = SecretKey::from_bytes(secret_key)
        .map_err(|_| SdkError::Kem("Invalid secret key".to_string()))?;

    let ct = Ciphertext::from_bytes(&encrypted[..KEM_CIPHERTEXT_SIZE])
        .map_err(|_| SdkError::InvalidCiphertext)?;

    let shared_secret = p384_mlkem1024::decapsulate(&sk, &ct);
    let decryption_key = shared_secret.derive_key();

    let encrypted_data = &encrypted[KEM_CIPHERTEXT_SIZE..];
    decrypt_aes_gcm(&decryption_key, encrypted_data)
}

pub fn encrypt_data(kem_secret_key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let key = hkdf_expand_to_key(kem_secret_key, b"confide_self_encrypt");
    encrypt_aes_gcm(key.deref(), data)
}

pub fn decrypt_data(kem_secret_key: &[u8], encrypted: &[u8]) -> Result<Vec<u8>> {
    let key = hkdf_expand_to_key(kem_secret_key, b"confide_self_encrypt");
    decrypt_aes_gcm(key.deref(), encrypted)
}

pub fn encrypt_with_channel_key(channel_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt_aes_gcm(channel_key, plaintext)
}

pub fn decrypt_with_channel_key(channel_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    decrypt_aes_gcm(channel_key, ciphertext)
}

pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let pk = PublicKey::from_bytes(public_key)
        .map_err(|_| SdkError::Kem("Invalid public key".to_string()))?;

    let (ciphertext, shared_secret) = p384_mlkem1024::encapsulate(&pk, &mut OsRng);

    Ok((ciphertext.as_bytes().to_vec(), shared_secret.derive_key()))
}

pub fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<[u8; 32]> {
    let sk = SecretKey::from_bytes(secret_key)
        .map_err(|_| SdkError::Kem("Invalid secret key".to_string()))?;

    let ct = Ciphertext::from_bytes(ciphertext).map_err(|_| SdkError::InvalidCiphertext)?;

    let shared_secret = p384_mlkem1024::decapsulate(&sk, &ct);

    Ok(shared_secret.derive_key())
}
