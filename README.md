# Rust-Chain

Componenti principali che arriveremo a Implementare

- Componente Crittografica
- transazioni
- blocchi
- Blockchain stessa
- Nodi
- Protocolli di Consenso
- Rete P2P
- Server RPC

Hashing: 
- SHA256 -> Bitcoin
- Keccak-256 (variante SHA3) -> Ethereum

Algoritmo Hash per Quantum : K12 (KangarooTwelve)
(non standardizzato)

partire da qui:
ed25519 start from here ed25519_dalek

poi aggiungere anche secp256k1



1 algoritmo hashing e uno di firma digitale, e implementare test (#[cfg(test)])

quindi chaincore -> src -> crypto : ed25519.rs e sha3.rs (cerca Crate sha3 etc.)

firmare un messaggio e hashare un messaggio