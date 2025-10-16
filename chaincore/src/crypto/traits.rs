
pub trait BlockchainSigner {
    type PrivateKey;
    type PublicKey;
    type Signature;
    type Error;

    fn generate(&self) -> Self::PrivateKey;
    fn get_public_key(&self, private_key: &Self::PrivateKey) -> Self::PublicKey;
    fn sign(&self, private_key: &Self::PrivateKey, message: &[u8]) -> Result<Self::Signature, Self::Error>;
    fn verify(&self,public_key: &Self::PublicKey, message:&[u8], sign: &Self::Signature) -> bool;
}

pub trait BlockchainHasher {
    type Output;
    
    fn hash(&self, message: &[u8]) -> Self::Output;
    fn hash_hex(&self, message: &[u8]) -> String;
}
