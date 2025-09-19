use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier, SignatureError};
use rand_core::OsRng;

pub fn generate_keypair() -> SigningKey {
    let mut csprng = OsRng;
    SigningKey::generate(&mut csprng)
}

pub fn get_public_key(signing_key : &SigningKey) -> VerifyingKey {
    signing_key.verifying_key()
}

pub fn sign_message(signing_key : &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}

pub fn verify_signature(signature: &Signature, pub_key: &VerifyingKey, message: &[u8]) -> bool {
    pub_key.verify(message, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sign_message() {
        let m = "test di messaggio da firmare";
        let keys = generate_keypair();
        let pub_key = get_public_key(&keys);
        let signature = sign_message(&keys, m.as_bytes());
        let is_valid = verify_signature(&signature, &pub_key, m.as_bytes());
        assert!(is_valid);
    }

    #[test]
    fn test_trait_implementation() {
        let signer = Ed25519Signer;
        let key = signer.generate();
        let pub_key = signer.get_public_key(&key);
        let m = b"test implementazione trait";
        let signature  = signer.sign(&key, m).unwrap();
        let is_valid = signer.verify(&pub_key, m, &signature );

        assert!(is_valid);
    }
}

use crate::crypto::traits::BlockchainSigner;
pub struct Ed25519Signer;

impl BlockchainSigner for Ed25519Signer {
    type PrivateKey = SigningKey;
    type PublicKey = VerifyingKey;
    type Signature = Signature;
    type Error = SignatureError;

    fn generate(&self) -> Self::PrivateKey {
        generate_keypair()
    }

    fn get_public_key(&self, private_key: &Self::PrivateKey) -> Self::PublicKey {
        get_public_key(private_key)
    }

    fn sign(&self, private_key: &Self::PrivateKey, message: &[u8]) -> Result<Self::Signature, Self::Error> {
        Ok(sign_message(private_key, message))
    }

    fn verify(&self,public_key: &Self::PublicKey, message:&[u8], sign: &Self::Signature) -> bool {
        verify_signature(sign, public_key, message)
    }
}
