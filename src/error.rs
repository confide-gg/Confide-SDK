use thiserror::Error;

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Ratchet state error: {0}")]
    RatchetState(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("KEM error: {0}")]
    Kem(String),

    #[error("Invalid ciphertext")]
    InvalidCiphertext,

    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Invalid prekey")]
    InvalidPrekey,

    #[error("Session not initialized")]
    SessionNotInitialized,

    #[error("Invalid key bundle")]
    InvalidKeyBundle,

    #[error("Group state error: {0}")]
    GroupState(String),

    #[error("Chain iteration mismatch")]
    ChainIterationMismatch,

    #[error("Group call error: {0}")]
    GroupCall(String),

    #[error("Group call full: max {0} participants")]
    GroupCallFull(usize),

    #[error("Participant not found")]
    ParticipantNotFound,

    #[error("Replay attack detected")]
    ReplayAttack,

    #[error("Key ID mismatch")]
    KeyIdMismatch,
}

pub type Result<T> = std::result::Result<T, SdkError>;
