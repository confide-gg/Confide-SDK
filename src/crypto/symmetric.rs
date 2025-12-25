use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    PasswordVerifier, Version,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Result, SdkError};

pub const AES_KEY_SIZE: usize = 32;
pub const AES_NONCE_SIZE: usize = 12;
pub const ARGON2_SALT_SIZE: usize = 32;

#[derive(Debug, Clone)]
pub struct Argon2Config {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            memory_kib: 65536,
            iterations: 3,
            parallelism: 4,
        }
    }
}

pub fn hash_password(password: &str, config: &Argon2Config) -> Result<Vec<u8>> {
    let salt = SaltString::generate(&mut OsRng);

    let params = Params::new(
        config.memory_kib,
        config.iterations,
        config.parallelism,
        None,
    )
    .map_err(|e| SdkError::KeyDerivation(format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| SdkError::KeyDerivation(format!("Argon2 hashing failed: {}", e)))?;

    Ok(hash.to_string().into_bytes())
}

pub fn verify_password(password: &str, hash: &[u8]) -> Result<bool> {
    let hash_str = std::str::from_utf8(hash)
        .map_err(|e| SdkError::KeyDerivation(format!("Invalid hash encoding: {}", e)))?;

    let parsed_hash = PasswordHash::new(hash_str)
        .map_err(|e| SdkError::KeyDerivation(format!("Invalid password hash: {}", e)))?;

    let argon2 = Argon2::default();

    Ok(argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn derive_key_argon2(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; AES_KEY_SIZE]>> {
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| SdkError::KeyDerivation(format!("Invalid salt: {}", e)))?;

    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| SdkError::KeyDerivation(format!("Argon2 failed: {}", e)))?;

    let hash_bytes = hash
        .hash
        .ok_or_else(|| SdkError::KeyDerivation("Argon2 produced no hash".to_string()))?;

    let bytes = hash_bytes.as_bytes();
    let mut key = Zeroizing::new([0u8; AES_KEY_SIZE]);
    let copy_len = bytes.len().min(AES_KEY_SIZE);
    key[..copy_len].copy_from_slice(&bytes[..copy_len]);

    Ok(key)
}

pub fn hkdf_expand(ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hkdf = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = vec![0u8; len];
    hkdf.expand(info, &mut okm)
        .expect("HKDF expand should not fail with valid length");
    okm
}

pub fn hkdf_expand_to_key(ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; AES_KEY_SIZE]> {
    let hkdf = Hkdf::<Sha256>::new(None, ikm);
    let mut key = Zeroizing::new([0u8; AES_KEY_SIZE]);
    hkdf.expand(info, key.as_mut())
        .expect("HKDF expand should not fail with 32-byte output");
    key
}

pub fn hkdf_derive_chain_keys(
    root_key: &[u8],
    shared_secret: &[u8],
) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mut combined = Vec::with_capacity(root_key.len() + shared_secret.len());
    combined.extend_from_slice(root_key);
    combined.extend_from_slice(shared_secret);

    let hkdf = Hkdf::<Sha256>::new(None, &combined);

    let mut new_root = Zeroizing::new([0u8; 32]);
    let mut chain_key = Zeroizing::new([0u8; 32]);

    hkdf.expand(b"confide_root", new_root.as_mut())
        .expect("HKDF expand should not fail");
    hkdf.expand(b"confide_chain", chain_key.as_mut())
        .expect("HKDF expand should not fail");

    (new_root, chain_key)
}

pub fn encrypt_aes_gcm(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != AES_KEY_SIZE {
        return Err(SdkError::InvalidKeyLength {
            expected: AES_KEY_SIZE,
            actual: key.len(),
        });
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SdkError::Encryption(format!("Failed to create cipher: {}", e)))?;

    let nonce_bytes = generate_random_bytes(AES_NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes.as_slice());

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| SdkError::Encryption(format!("AES-GCM encryption failed: {}", e)))?;

    let mut result = Vec::with_capacity(AES_NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

pub fn decrypt_aes_gcm(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != AES_KEY_SIZE {
        return Err(SdkError::InvalidKeyLength {
            expected: AES_KEY_SIZE,
            actual: key.len(),
        });
    }

    if ciphertext.len() < AES_NONCE_SIZE {
        return Err(SdkError::InvalidCiphertext);
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| SdkError::Decryption(format!("Failed to create cipher: {}", e)))?;

    let nonce = Nonce::from_slice(&ciphertext[..AES_NONCE_SIZE]);
    let encrypted_data = &ciphertext[AES_NONCE_SIZE..];

    cipher
        .decrypt(nonce, encrypted_data)
        .map_err(|e| SdkError::Decryption(format!("AES-GCM decryption failed: {}", e)))
}

pub fn derive_message_key(chain_key: &[u8]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let message_key = hkdf_expand_to_key(chain_key, b"confide_message");
    let new_chain_key = hkdf_expand_to_key(chain_key, b"confide_chain_advance");
    (message_key, new_chain_key)
}
