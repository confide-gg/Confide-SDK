use rand::{rngs::OsRng, Rng};
use rustpq::ml_dsa::mldsa87;
use rustpq::ml_kem_hybrid::p384_mlkem1024;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{Result, SdkError};

#[derive(Clone, Serialize, Deserialize)]
pub struct SignedPrekey {
    pub prekey_id: i32,
    pub public_key: Vec<u8>,
    #[serde(skip_serializing)]
    pub secret_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Zeroize for SignedPrekey {
    fn zeroize(&mut self) {
        self.secret_key.zeroize();
    }
}

impl Drop for SignedPrekey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SignedPrekey {
    pub fn into_parts(self) -> (i32, Vec<u8>, Vec<u8>, Vec<u8>) {
        let prekey_id = self.prekey_id;
        let public_key = self.public_key.clone();
        let secret_key = self.secret_key.clone();
        let signature = self.signature.clone();
        (prekey_id, public_key, secret_key, signature)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OneTimePrekey {
    pub prekey_id: i32,
    pub public_key: Vec<u8>,
    #[serde(skip_serializing)]
    pub secret_key: Vec<u8>,
}

impl Zeroize for OneTimePrekey {
    fn zeroize(&mut self) {
        self.secret_key.zeroize();
    }
}

impl Drop for OneTimePrekey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl OneTimePrekey {
    pub fn into_parts(self) -> (i32, Vec<u8>, Vec<u8>) {
        let prekey_id = self.prekey_id;
        let public_key = self.public_key.clone();
        let secret_key = self.secret_key.clone();
        (prekey_id, public_key, secret_key)
    }
}

pub fn generate_signed_prekey_from_secret(dsa_secret_key: &[u8]) -> Result<SignedPrekey> {
    let (pk, sk) = p384_mlkem1024::generate(&mut OsRng);

    let prekey_id: i32 = OsRng.gen_range(1..i32::MAX);
    let public_key = pk.as_bytes().to_vec();

    let dsa_sk =
        mldsa87::SecretKey::from_bytes(dsa_secret_key).map_err(|_| SdkError::InvalidSignature)?;

    let signature = mldsa87::sign(&dsa_sk, &public_key, b"", &mut OsRng)
        .map_err(|e| SdkError::Encryption(format!("Signing failed: {:?}", e)))?;

    Ok(SignedPrekey {
        prekey_id,
        public_key,
        secret_key: sk.as_bytes().to_vec(),
        signature: signature.as_bytes().to_vec(),
    })
}

pub fn generate_one_time_prekeys(count: u32) -> Vec<OneTimePrekey> {
    let mut prekeys = Vec::with_capacity(count as usize);

    for _ in 0..count {
        let (pk, sk) = p384_mlkem1024::generate(&mut OsRng);
        let prekey_id: i32 = OsRng.gen_range(1..i32::MAX);

        prekeys.push(OneTimePrekey {
            prekey_id,
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        });
    }

    prekeys
}

pub fn verify_signed_prekey(
    dsa_public_key: &[u8],
    prekey_public: &[u8],
    signature: &[u8],
) -> Result<bool> {
    let pk =
        mldsa87::PublicKey::from_bytes(dsa_public_key).map_err(|_| SdkError::InvalidSignature)?;

    let sig = mldsa87::Signature::from_bytes(signature).map_err(|_| SdkError::InvalidSignature)?;

    match mldsa87::verify(&pk, prekey_public, b"", &sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}
