pub mod crypto;
pub mod transaction;
pub mod block;
pub mod blockchain;
pub mod config;

pub use crypto::crypto::{BlockchainSigner, BlockchainHasher, TaggedBlockchainHasher, CryptoEncoding};

// transaction types
pub use transaction::transaction::{OutPoint, TxInput, TxOutput, Transaction, TxCodec, Sighash, UtxoView};

// block types
pub use block::Block;

// blockchain types
pub use blockchain::{Blockchain, UtxoSet};

// configuration (type alias configurabili)
pub use config::{DefaultSigner, DefaultHasher, PrivateKey, PublicKey, Signature, HashOutput, SIGNER, HASHER};

