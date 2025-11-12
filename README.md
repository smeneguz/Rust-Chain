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


LEZIONE 2:
cryptobackend guardare features (riguardare trait)

Le transazioni servono per cambio di stato nel sistema (deterministico)
tre elementi : mittente, destinatario, firma digitale (autenticità)
- mittente in ethereum non esiste perchè ha 3 paramtri r,s,v e questi possono derivare il mittente quindi non serve specificarlo

chiave privata e chave pubblica, indirizzo (versione più corta della chiave pubblica)

modelli di gestione dello stato UTXO e account model
- modello UTXO prevede un certo numero di input e un certo numero di output
- modello account based, ..

scegliamo modello UTXO
definiamo struttura transazione come mittente, destinatario,importo, firma
scegliere crittografia
imnplementare logica che valida transazioni assicurandosi che rispettino le regole del protocoolo (utilizzare UTXO non già utilizzato, decisiamo input, output ) , scegliere come fatta una transazione
- implementare meccanismi per doppia spesa e garantire integrità

definito transazione come struct con id array di byte e una copia di proprietà input e output vec<TransactionInput> e vec<TransactionOutput>
poi implementazione trait has duplicate inputs (non ci sia du volte stesso input)

se è valida is_valid se non ha steso input due volte semplicemente

create_id della transazione che è un hash di tutti quanti input e output insieme

e funzione create transazion

structu input con funziopni per firmare un input (garantire che si io che posso usarlo), crearlo , e verificato (previous_tx_id transaction hash, output_index, signature, public_key) output non speso che voglio utilizzare lo individuo con i primi due campi

struct TransactionOutput chi riceve i soldi e quanti 

e idea di blocco , pub struct Block con campi corretti

iniziare a pensare a questo modello UTXO , c abozzare modulo transaction dove abozziamo prototipale transaction 
transaction.rs
#derive (debug, Clone, ...) 


Gian:

Transaction input : struttura con previous_tx_hash, output_index, signature, public_key


hashmap metterò più avanti nel modulo blockchain 

BLOCCO MODULO DA FARE adesso e prossimo modulo blockchain

blocco e blockchain by Gian: 
blocco: index, hash, previous_block_hash, timestamp, transaction, author, signature, metadata

hash di tutto 

blockcahin: 