#![allow(unused_assignments)]

use rand::rngs::OsRng;
use rustpq::ml_kem_hybrid::p384_mlkem1024;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CallKeyPair {
    #[zeroize(skip)]
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

impl CallKeyPair {
    pub fn generate() -> Self {
        let (pk, sk) = p384_mlkem1024::generate(&mut OsRng);
        Self {
            public: pk.as_bytes().to_vec(),
            secret: sk.as_bytes().to_vec(),
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CallMediaKeys {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
}
