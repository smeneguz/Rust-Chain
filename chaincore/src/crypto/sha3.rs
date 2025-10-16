use sha3::{Digest, Sha3_256};
use hex;

//TODO Vec di ritorno non è necessario sapendo che sarà sempre 32 quindi si potrebbe modificare con [u8;32]
pub fn hash_message(m : &[u8]) -> Vec<u8> {
	let mut hasher = Sha3_256::new();
    hasher.update(m);
    let result = hasher.finalize();
    result.to_vec()
}

pub fn hash_string(text: &str) -> Vec<u8> {
    hash_message(text.as_bytes())
}

pub fn hash_to_hex(hash: &[u8]) -> String {
    hex::encode(hash)
}

// Calcola hash e ritorna direttamente in formato hex
pub fn hash_message_hex(message: &[u8]) -> String {
    let hash = hash_message(message);
    hash_to_hex(&hash)
}

// Versione che combina string hash + hex
pub fn hash_string_hex(text: &str) -> String {
    hash_message_hex(text.as_bytes())
}

// se può servire aggiungo anche da hex verso bytes
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

    #[test]
        fn test_hex_conversion_trait() {
        let hasher = Sha3Hasher;
        let m = b"test";
        let hex_string = hasher.hash_hex(m);

        assert_eq!(hex_string.len(), 64);
        assert!(hex_string.chars().all(|c| c.is_ascii_hexdigit()));
    }

}

use crate::crypto::traits::BlockchainHasher;

pub struct Sha3Hasher;

impl BlockchainHasher for Sha3Hasher {
    type Output = [u8; 32]; // it will be alwasys 32 bytes

    fn hash(&self, message: &[u8]) -> Self::Output {
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        hasher.finalize().into()
    }

    fn hash_hex(&self, message: &[u8]) -> String {
        hex::encode(self.hash(message).as_ref())
    }
}