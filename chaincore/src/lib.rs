pub mod crypto;
pub mod transaction;
pub mod block;
pub mod blockchain;
pub mod config;

// Re-export crypto traits
pub use crypto::crypto::{BlockchainSigner, BlockchainHasher, TaggedBlockchainHasher, CryptoEncoding};

// Re-export transaction types
pub use transaction::transaction::{OutPoint, TxInput, TxOutput, Transaction, TxCodec, Sighash, UtxoView};

// Re-export block types
pub use block::Block;

// Re-export blockchain types
pub use blockchain::{Blockchain, UtxoSet};

// Re-export configuration (type alias configurabili)
pub use config::{DefaultSigner, DefaultHasher, PrivateKey, PublicKey, Signature, HashOutput, SIGNER, HASHER};

