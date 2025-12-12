use std::ops::Deref;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::keys::{DecryptedKeys, EncryptedKeys};
use super::symmetric::{decrypt_aes_gcm, encrypt_aes_gcm, generate_random_bytes, ARGON2_SALT_SIZE};
use crate::error::Result;

#[derive(Clone, Serialize, Deserialize)]
pub struct RecoveryKeyData {
    pub recovery_key: Vec<u8>,
    pub recovery_kem_encrypted_private: Vec<u8>,
    pub recovery_dsa_encrypted_private: Vec<u8>,
    pub recovery_key_salt: Vec<u8>,
}

impl Zeroize for RecoveryKeyData {
    fn zeroize(&mut self) {
        self.recovery_key.zeroize();
    }
}

impl Drop for RecoveryKeyData {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl RecoveryKeyData {
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let recovery_key = self.recovery_key.clone();
        let kem_enc = self.recovery_kem_encrypted_private.clone();
        let dsa_enc = self.recovery_dsa_encrypted_private.clone();
        let salt = self.recovery_key_salt.clone();
        (recovery_key, kem_enc, dsa_enc, salt)
    }
}

pub fn generate_recovery_key() -> Vec<u8> {
    generate_random_bytes(32)
}

pub fn encrypt_keys_with_recovery(
    recovery_key: &[u8],
    kem_secret_key: &[u8],
    dsa_secret_key: &[u8],
) -> Result<RecoveryKeyData> {
    let salt = generate_random_bytes(ARGON2_SALT_SIZE);
    let encryption_key = derive_key_argon2_from_bytes(recovery_key, &salt)?;

    let kem_encrypted = encrypt_aes_gcm(encryption_key.deref(), kem_secret_key)?;
    let dsa_encrypted = encrypt_aes_gcm(encryption_key.deref(), dsa_secret_key)?;

    Ok(RecoveryKeyData {
        recovery_key: recovery_key.to_vec(),
        recovery_kem_encrypted_private: kem_encrypted,
        recovery_dsa_encrypted_private: dsa_encrypted,
        recovery_key_salt: salt,
    })
}

pub fn decrypt_keys_with_recovery(
    recovery_key: &[u8],
    kem_encrypted_private: &[u8],
    dsa_encrypted_private: &[u8],
    recovery_key_salt: &[u8],
) -> Result<DecryptedKeys> {
    let encryption_key = derive_key_argon2_from_bytes(recovery_key, recovery_key_salt)?;

    let kem_secret = decrypt_aes_gcm(encryption_key.deref(), kem_encrypted_private)?;
    let dsa_secret = decrypt_aes_gcm(encryption_key.deref(), dsa_encrypted_private)?;

    Ok(DecryptedKeys {
        kem_public_key: Vec::new(),
        kem_secret_key: kem_secret,
        dsa_public_key: Vec::new(),
        dsa_secret_key: dsa_secret,
    })
}

pub fn re_encrypt_keys_for_new_password(
    password: &str,
    recovery_key: &[u8],
    kem_public_key: &[u8],
    kem_secret_key: &[u8],
    dsa_public_key: &[u8],
    dsa_secret_key: &[u8],
) -> Result<(EncryptedKeys, RecoveryKeyData)> {
    let salt = generate_random_bytes(ARGON2_SALT_SIZE);
    let password_key = super::symmetric::derive_key_argon2(password, &salt)?;

    let kem_encrypted = encrypt_aes_gcm(password_key.deref(), kem_secret_key)?;
    let dsa_encrypted = encrypt_aes_gcm(password_key.deref(), dsa_secret_key)?;

    let encrypted_keys = EncryptedKeys {
        kem_public_key: kem_public_key.to_vec(),
        kem_encrypted_private: kem_encrypted,
        dsa_public_key: dsa_public_key.to_vec(),
        dsa_encrypted_private: dsa_encrypted,
        key_salt: salt,
    };

    let recovery_data = encrypt_keys_with_recovery(recovery_key, kem_secret_key, dsa_secret_key)?;

    Ok((encrypted_keys, recovery_data))
}

fn derive_key_argon2_from_bytes(
    key_bytes: &[u8],
    salt: &[u8],
) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let key_hex = hex::encode(key_bytes);
    super::symmetric::derive_key_argon2(&key_hex, salt)
}
