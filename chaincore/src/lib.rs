pub mod crypto;
pub mod transaction;

pub use crypto::traits::{BlockchainSigner, BlockchainHasher};

// Ed25519 Implementation
pub use crypto::ed25519::{
    Ed25519Signer,
    generate_keypair,
    get_public_key,
    sign_message,
    verify_signature,
};

// SHA3 Implementation
pub use crypto::sha3::{
    Sha3Hasher,
    hash_message,
    hash_string,
    hash_to_hex,
    hash_message_hex,
    hash_string_hex,
    hex_to_bytes,
};

// Transaction Traits
pub use transaction::traits::{
    TransactionModel,
    TransactionOutputModel,
    TransactionInputModel,
};

// UTXO Implementation
pub use transaction::utxo::{
    UtxoOutput,
    // UtxoInput,        // TODO: Implementare
    // UtxoTransaction,  // TODO: Implementare
};

// UTXO Helper Functions
pub use transaction::utxo::output::{
    create_output,
    is_output_owned_by,
    output_to_bytes,
};