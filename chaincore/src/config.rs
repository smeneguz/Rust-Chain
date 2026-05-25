// "type alias" per gli algoritmi crittografici

use crate::crypto::{Ed25519Signer, Sha3Hasher};
use crate::crypto::*;

//TODO Alternative future: Secp256k1, Schnorr, Dilithium (post-quantum)
pub type DefaultSigner = Ed25519Signer;
pub type DefaultHasher = Sha3Hasher;

pub type PrivateKey = <DefaultSigner as BlockchainSigner>::PrivateKey;
pub type PublicKey = <DefaultSigner as BlockchainSigner>::PublicKey;
pub type Signature = <DefaultSigner as BlockchainSigner>::Signature;
pub type HashOutput = <DefaultHasher as BlockchainHasher>::Output;


// Istanza globale del signer
pub const SIGNER: DefaultSigner = Ed25519Signer;
// Istanza globale dell'hasher
pub const HASHER: DefaultHasher = Sha3Hasher;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::BlockchainSigner;
    
    #[test]
    fn test_config_usage() {
        // type alias
        let private_key: PrivateKey = SIGNER.generate();
        let public_key: PublicKey = SIGNER.get_public_key(&private_key);
        
        let message = b"test configurazione";
        let signature: Signature = SIGNER.sign(&private_key, message).unwrap();
        
        assert!(SIGNER.verify(&public_key, message, &signature));
    }
}
