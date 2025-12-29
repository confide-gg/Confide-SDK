use serde::{Deserialize, Serialize};

use super::types::CALL_ID_SIZE;

#[derive(Clone, Serialize, Deserialize)]
pub struct CallOffer {
    pub call_id: [u8; CALL_ID_SIZE],
    pub caller_id: [u8; CALL_ID_SIZE],
    pub callee_id: [u8; CALL_ID_SIZE],
    pub ephemeral_kem_public: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CallAnswer {
    pub call_id: [u8; CALL_ID_SIZE],
    pub ephemeral_kem_public: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CallKeyExchangeComplete {
    pub call_id: [u8; CALL_ID_SIZE],
    pub kem_ciphertext: Vec<u8>,
}
