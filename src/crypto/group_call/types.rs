use serde::{Deserialize, Serialize};

use super::symmetric::generate_random_bytes;
use crate::error::{Result, SdkError};

pub const MAX_GROUP_CALL_PARTICIPANTS: usize = 10;
pub const GROUP_CALL_ID_SIZE: usize = 16;
pub const PARTICIPANT_ID_SIZE: usize = 16;

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupCallId(pub [u8; GROUP_CALL_ID_SIZE]);

impl GroupCallId {
    pub fn new() -> Self {
        let mut id = [0u8; GROUP_CALL_ID_SIZE];
        let random = generate_random_bytes(GROUP_CALL_ID_SIZE);
        id.copy_from_slice(&random);
        Self(id)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != GROUP_CALL_ID_SIZE {
            return Err(SdkError::InvalidKeyLength {
                expected: GROUP_CALL_ID_SIZE,
                actual: bytes.len(),
            });
        }
        let mut id = [0u8; GROUP_CALL_ID_SIZE];
        id.copy_from_slice(bytes);
        Ok(Self(id))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Default for GroupCallId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParticipantId(pub [u8; PARTICIPANT_ID_SIZE]);

impl ParticipantId {
    pub fn new() -> Self {
        let mut id = [0u8; PARTICIPANT_ID_SIZE];
        let random = generate_random_bytes(PARTICIPANT_ID_SIZE);
        id.copy_from_slice(&random);
        Self(id)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PARTICIPANT_ID_SIZE {
            return Err(SdkError::InvalidKeyLength {
                expected: PARTICIPANT_ID_SIZE,
                actual: bytes.len(),
            });
        }
        let mut id = [0u8; PARTICIPANT_ID_SIZE];
        id.copy_from_slice(bytes);
        Ok(Self(id))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Default for ParticipantId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaType {
    Audio = 1,
    Video = 2,
    Screenshare = 3,
}

impl MediaType {
    pub fn nonce_prefix(&self) -> u8 {
        match self {
            MediaType::Audio => 0x01,
            MediaType::Video => 0x02,
            MediaType::Screenshare => 0x03,
        }
    }
}
