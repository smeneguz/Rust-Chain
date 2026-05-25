use crate::config::{HashOutput, PublicKey, Signature};
use crate::transaction::Transaction;
use crate::config::HASHER;
use crate::crypto::BlockchainHasher;
use crate::crypto::CryptoEncoding;
use crate::config::SIGNER;

#[derive(Debug, Clone)]
pub struct Block {
    pub hash: HashOutput,
    pub index: u32,
    pub prev_block_hash: HashOutput,
    pub timestamp: u128,    
    pub transactions: Vec<Transaction>,    
    pub author: PublicKey,
    pub signature: Option<Signature>,
}

impl Block {
    // Crea un nuovo blocco (senza firma)
    // Il blocco deve essere firmato separatamente con `sign_block()`
    pub fn new(
        index: u32,
        prev_block_hash: HashOutput,
        transactions: Vec<Transaction>,
        author: PublicKey,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis();
        
        Self {
            hash: [0u8; 32], // Verrà calcolato dopo la firma
            index,
            prev_block_hash,
            timestamp,
            transactions,
            author,
            signature: None, // Blocco non ancora firmato
        }
    }
    

    pub fn genesis(author: PublicKey) -> Self {
        Self::new(
            0,
            [0u8; 32],  // Nessun blocco precedente
            Vec::new(), // Nessuna transazione (o aggiungi coinbase)
            author,
        )
    }
    
    // Numero di transazioni nel blocco
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }
    
    // Verifica se questo è il genesis block
    pub fn is_genesis(&self) -> bool {
        self.index == 0 && self.prev_block_hash == [0u8; 32]
    }
}

// Metodi per calcolo hash e firma
impl Block {
    // Prepara i dati da firmare/hashare
    // Serializza: index || prev_hash || timestamp || tx_hashes || author
    // (esclude hash e signature correnti)
    pub fn to_bytes_for_signing(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Index
        bytes.extend_from_slice(&self.index.to_le_bytes());
        
        // Previous block hash
        bytes.extend_from_slice(&self.prev_block_hash);
        
        // Timestamp
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        
        // Number of transactions
        bytes.extend_from_slice(&(self.transactions.len() as u32).to_le_bytes());
        
        // Transaction hashes (TXID di ogni transazione)
        for tx in &self.transactions {
            bytes.extend_from_slice(&tx.txid());
        }
        
        // Author public key
        bytes.extend_from_slice(&self.author.to_bytes());
        
        bytes
    }
    
    // Prepara i dati per il calcolo dell'hash finale 
    // Include TUTTO: index || prev_hash || timestamp || tx_hashes || author || signature
    // Questo garantisce che l'hash del blocco sia univoco e includa la prova di authorship
    fn to_bytes_for_hashing(&self) -> Vec<u8> {

        
        let mut bytes = self.to_bytes_for_signing();
        
        // Aggiungi signature se presente
        if let Some(ref sig) = self.signature {
            let sig_bytes = SIGNER.sig_to_bytes(sig.clone());
            bytes.extend_from_slice(&(sig_bytes.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&sig_bytes);
        }
        
        bytes
    }
    
    /// Calcola l'hash del blocco
    /// 
    /// L'hash include la signature per garantire univocità e proof of authorship
    pub fn calculate_hash(&self) -> HashOutput {
        HASHER.hash(&self.to_bytes_for_hashing())
    }
    
    /// Firma il blocco e calcola l'hash
    /// 
    /// Questo metodo:
    /// 1. Firma i dati del blocco
    /// 2. Calcola l'hash finale (inclusa la firma)
    /// 3. Aggiorna i campi hash e signature
    pub fn sign_and_finalize(&mut self, private_key: &crate::config::PrivateKey) -> Result<(), &'static str> {
        use crate::config::SIGNER;
        use crate::crypto::BlockchainSigner;
        
        // 1. Firma i dati del blocco
        let data = self.to_bytes_for_signing();
        let signature = SIGNER.sign(private_key, &data)
            .map_err(|_| "Failed to sign block")?;
        
        self.signature = Some(signature);
        
        // 2. Calcola hash finale (ora che abbiamo la firma)
        self.hash = self.calculate_hash();
        
        Ok(())
    }
    
    /// Verifica la firma del blocco
    pub fn verify_signature(&self) -> bool {
        use crate::config::SIGNER;
        use crate::crypto::BlockchainSigner;
        
        match &self.signature {
            None => false,
            Some(sig) => {
                let data = self.to_bytes_for_signing();
                SIGNER.verify(&self.author, &data, sig)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::crypto::BlockchainSigner;
    use crate::config::SIGNER;

    #[test]
    fn test_genesis_block() {
        let private_key = SIGNER.generate();
        let author = SIGNER.get_public_key(&private_key);
        let genesis = Block::genesis(author);
        
        assert_eq!(genesis.index, 0);
        assert_eq!(genesis.prev_block_hash, [0u8; 32]);
        assert_eq!(genesis.transaction_count(), 0);
        assert!(genesis.is_genesis());
    }

    #[test]
    fn test_block_creation() {
        let private_key = SIGNER.generate();
        let author = SIGNER.get_public_key(&private_key);
        let prev_hash = [1u8; 32];
        let block = Block::new(1, prev_hash, Vec::new(), author);
        
        assert_eq!(block.index, 1);
        assert_eq!(block.prev_block_hash, prev_hash);
        assert!(!block.is_genesis());
    }
    
    #[test]
    fn test_block_signing() {
        let private_key = SIGNER.generate();
        let author = SIGNER.get_public_key(&private_key);
        
        let mut block = Block::genesis(author);
        
        // Blocco non ancora firmato
        assert!(block.signature.is_none());
        assert!(!block.verify_signature());
        
        // Firma il blocco
        assert!(block.sign_and_finalize(&private_key).is_ok());
        
        // Ora è firmato
        assert!(block.signature.is_some());
        assert!(block.verify_signature());
        
        // Hash non deve essere zero
        assert_ne!(block.hash, [0u8; 32]);
    }
    
    #[test]
    fn test_block_hash_deterministic() {
        let private_key = SIGNER.generate();
        let author = SIGNER.get_public_key(&private_key);
        
        let mut block1 = Block::new(1, [1u8; 32], Vec::new(), author);
        let mut block2 = Block::new(1, [1u8; 32], Vec::new(), author);
        
        // Stessi parametri -> stesso hash prima della firma
        let hash1_before = block1.calculate_hash();
        let hash2_before = block2.calculate_hash();
        assert_eq!(hash1_before, hash2_before);
        
        // Firma entrambi con la stessa chiave
        block1.sign_and_finalize(&private_key).unwrap();
        block2.sign_and_finalize(&private_key).unwrap();
        
        // Hash finali devono essere uguali (firma deterministica)
        assert_eq!(block1.hash, block2.hash);
    }
    
    #[test]
    fn test_hash_includes_signature() {
        let private_key = SIGNER.generate();
        let author = SIGNER.get_public_key(&private_key);
        
        let mut block = Block::genesis(author);
        
        // Hash prima della firma (senza signature)
        let hash_unsigned = block.calculate_hash();
        
        // Firma il blocco
        block.sign_and_finalize(&private_key).unwrap();
        
        // Hash dopo la firma (con signature)
        let hash_signed = block.hash;
        
        // Gli hash DEVONO essere diversi (prova che signature è inclusa nell'hash)
        assert_ne!(hash_unsigned, hash_signed, 
            "Block hash must change after signing - signature must be included in hash");
        
        // Ricalcola hash - deve essere uguale (deterministic)
        let hash_recalculated = block.calculate_hash();
        assert_eq!(hash_signed, hash_recalculated);
    }
}
