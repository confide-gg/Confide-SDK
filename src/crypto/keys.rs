use std::ops::Deref;

use rand::rngs::OsRng;
use rustpq::ml_dsa::mldsa87;
use rustpq::ml_kem_hybrid::p384_mlkem1024;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::symmetric::{
    decrypt_aes_gcm, derive_key_argon2, encrypt_aes_gcm, generate_random_bytes, ARGON2_SALT_SIZE,
};
use crate::error::{Result, SdkError};

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedKeys {
    pub kem_public_key: Vec<u8>,
    pub kem_encrypted_private: Vec<u8>,
    pub dsa_public_key: Vec<u8>,
    pub dsa_encrypted_private: Vec<u8>,
    pub key_salt: Vec<u8>,
}

#[derive(Clone)]
pub struct DecryptedKeys {
    pub kem_public_key: Vec<u8>,
    pub kem_secret_key: Vec<u8>,
    pub dsa_public_key: Vec<u8>,
    pub dsa_secret_key: Vec<u8>,
}

impl Zeroize for DecryptedKeys {
    fn zeroize(&mut self) {
        self.kem_secret_key.zeroize();
        self.dsa_secret_key.zeroize();
    }
}

impl Drop for DecryptedKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl DecryptedKeys {
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let kem_pub = self.kem_public_key.clone();
        let kem_sec = self.kem_secret_key.clone();
        let dsa_pub = self.dsa_public_key.clone();
        let dsa_sec = self.dsa_secret_key.clone();
        (kem_pub, kem_sec, dsa_pub, dsa_sec)
    }
}

pub struct DsaKeyPair {
    pub public: Vec<u8>,
    secret: Zeroizing<Vec<u8>>,
}

impl DsaKeyPair {
    pub fn generate() -> Self {
        let (pk, sk) = mldsa87::generate(&mut OsRng);
        Self {
            public: pk.as_bytes().to_vec(),
            secret: Zeroizing::new(sk.as_bytes().to_vec()),
        }
    }

    pub fn from_bytes(public: &[u8], secret: &[u8]) -> Result<Self> {
        Ok(Self {
            public: public.to_vec(),
            secret: Zeroizing::new(secret.to_vec()),
        })
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sk =
            mldsa87::SecretKey::from_bytes(&self.secret).map_err(|_| SdkError::InvalidSignature)?;

        let signature = mldsa87::sign(&sk, message, b"", &mut OsRng)
            .map_err(|e| SdkError::Encryption(format!("Signing failed: {:?}", e)))?;

        Ok(signature.as_bytes().to_vec())
    }

    pub fn verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        let pk = mldsa87::PublicKey::from_bytes(public).map_err(|_| SdkError::InvalidSignature)?;

        let sig =
            mldsa87::Signature::from_bytes(signature).map_err(|_| SdkError::InvalidSignature)?;

        match mldsa87::verify(&pk, message, b"", &sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub fn secret_bytes(&self) -> &[u8] {
        &self.secret
    }
}

pub fn generate_and_encrypt_keys(password: &str) -> Result<EncryptedKeys> {
    let (kem_pk, kem_sk) = p384_mlkem1024::generate(&mut OsRng);
    let (dsa_pk, dsa_sk) = mldsa87::generate(&mut OsRng);

    let salt = generate_random_bytes(ARGON2_SALT_SIZE);
    let encryption_key = derive_key_argon2(password, &salt)?;

    let kem_sk_bytes = kem_sk.as_bytes();
    let dsa_sk_bytes = dsa_sk.as_bytes();

    let kem_encrypted = encrypt_aes_gcm(encryption_key.deref(), kem_sk_bytes.as_ref())?;
    let dsa_encrypted = encrypt_aes_gcm(encryption_key.deref(), dsa_sk_bytes)?;

    Ok(EncryptedKeys {
        kem_public_key: kem_pk.as_bytes().to_vec(),
        kem_encrypted_private: kem_encrypted,
        dsa_public_key: dsa_pk.as_bytes().to_vec(),
        dsa_encrypted_private: dsa_encrypted,
        key_salt: salt,
    })
}

pub fn decrypt_keys(
    password: &str,
    kem_public_key: &[u8],
    kem_encrypted_private: &[u8],
    dsa_public_key: &[u8],
    dsa_encrypted_private: &[u8],
    key_salt: &[u8],
) -> Result<DecryptedKeys> {
    let encryption_key = derive_key_argon2(password, key_salt)?;

    let kem_secret = decrypt_aes_gcm(encryption_key.deref(), kem_encrypted_private)?;
    let dsa_secret = decrypt_aes_gcm(encryption_key.deref(), dsa_encrypted_private)?;

    Ok(DecryptedKeys {
        kem_public_key: kem_public_key.to_vec(),
        kem_secret_key: kem_secret,
        dsa_public_key: dsa_public_key.to_vec(),
        dsa_secret_key: dsa_secret,
    })
}

pub fn generate_kem_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = p384_mlkem1024::generate(&mut OsRng);
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

pub fn generate_dsa_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = mldsa87::generate(&mut OsRng);
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}
