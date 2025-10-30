
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

//  Estensione per "tagged hash" (BIP‑340/341): H( H(tag) || H(tag) || msg )
pub trait TaggedBlockchainHasher {
    fn hash_tagged(&self, tag: &'static [u8], msg: &[u8]) -> Self::Output;
}

// Codec per chiavi/firme <-> bytes. Così il livello transaction resta byte‐level.
pub trait CryptoEncoding {
    type PublicKey;
    type Signature;
    type Error;

    fn pk_to_bytes(&self, pk: &Self::PublicKey) -> Vec<u8>;
    fn pk_from_bytes(&self, b: &[u8]) -> Result<Self::PublicKey, Self::Error>;

    fn sig_to_bytes(&self, sig: Self::Signature) -> Vec<u8>;
    fn sig_from_bytes(&self, b: &[u8]) -> Result<Self::Signature, Self::Error>;
}