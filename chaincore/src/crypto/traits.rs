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
    fn hash(&self, message: &[u8]) -> Vec<u8>;
    fn read_hash(&self, message: &[u8]) -> String;
}