use sha3::{Digest, Sha3_256};
use hex;

pub fn hash_message(m: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(m);
    hasher.finalize().to_vec()
}

pub fn hash_string(text: &str) -> Vec<u8> {
    hash_message(text.as_bytes())
}

pub fn hash_to_hex(hash: &[u8]) -> String {
    hex::encode(hash)
}

pub fn hash_message_hex(message: &[u8]) -> String {
    hash_to_hex(&hash_message(message))
}

pub fn hash_string_hex(text: &str) -> String {
    hash_message_hex(text.as_bytes())
}

pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_hex_conversion() {
        let m = b"test";
        let hash = hash_message(m);
        let hex_string = hash_to_hex(&hash);
        assert_eq!(hex_string.len(), 64);
        assert!(hex_string.chars().all(|c| c.is_ascii_hexdigit()));
        let decoded = hex_to_bytes(&hex_string).unwrap();
        assert_eq!(hash, decoded);
    }
}

use crate::crypto::traits::{BlockchainHasher, TaggedBlockchainHasher};

/// Hasher SHA3-256
pub struct Sha3Hasher;

impl BlockchainHasher for Sha3Hasher {
    type Output = [u8; 32]; // sempre 32 byte

    fn hash(&self, message: &[u8]) -> Self::Output {
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        hasize(&mut hasher)
    }

    fn hash_hex(&self, message: &[u8]) -> String {
        hex::encode(self.hash(message).as_ref())
    }
}

impl TaggedBlockchainHasher for Sha3Hasher {
    fn hash_tagged(&self, tag: &'static [u8], msg: &[u8]) -> Self::Output {
        // H( H(tag) || H(tag) || msg )
        let t = self.hash(tag);
        let mut buf = Vec::with_capacity(64 + msg.len());
        buf.extend_from_slice(t.as_ref());
        buf.extend_from_slice(t.as_ref());
        buf.extend_from_slice(msg);
        self.hash(&buf)
    }
}

// piccolo helper per finalizzare in [u8;32]
fn hasize(hasher: &mut Sha3_256) -> [u8; 32] {
    use sha3::digest::FixedOutput;
    hasher.clone().finalize_fixed().into()
    //TODO aggiunto clone per errore in quando finalize fixed consuma l'input, capire cosa vuol dire in termini di performance
}
