pub mod backend;
pub mod core;
pub mod default;

#[cfg(feature = "sha3_256")]
pub mod sha3_256;

pub use backend::{CryptoHash, CryptoHasher, HashBackend};
pub use core::{Hash, Hashable, Hasher};
pub use default::{DefaultHash, DefaultHashBackend, DefaultHasher};

#[cfg(feature="sha3_256")]
pub use sha3_256::{Sha3_256Backend, Sha3_256Cryptohasher, Sha3_256Hash};