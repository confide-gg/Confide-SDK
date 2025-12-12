use sha2::{Digest, Sha256};

pub fn generate_safety_number(our_identity_key: &[u8], their_identity_key: &[u8]) -> String {
    let (first, second) = if our_identity_key < their_identity_key {
        (our_identity_key, their_identity_key)
    } else {
        (their_identity_key, our_identity_key)
    };

    let mut combined_hash = Vec::with_capacity(64);

    let mut hasher = Sha256::new();
    hasher.update(first);
    hasher.update(second);
    hasher.update(b"confide_safety_number_v1_part1");
    combined_hash.extend_from_slice(&hasher.finalize());

    let mut hasher2 = Sha256::new();
    hasher2.update(second);
    hasher2.update(first);
    hasher2.update(b"confide_safety_number_v1_part2");
    combined_hash.extend_from_slice(&hasher2.finalize());

    let mut numbers = Vec::with_capacity(12);
    for i in 0..12 {
        let start = i * 5;
        let end = (start + 5).min(combined_hash.len());
        let chunk = &combined_hash[start..end];

        let mut value: u64 = 0;
        for &byte in chunk {
            value = (value << 8) | (byte as u64);
        }
        numbers.push(format!("{:05}", value % 100000));
    }

    numbers.join(" ")
}
