use crate::block::Block;
use crate::transaction::{Transaction, OutPoint};
use crate::config::HashOutput;
use super::utxo_set::UtxoSet;

/// Blockchain - Catena di blocchi con UTXO set
/// 
/// Architettura:
/// 1. `blocks`: Storico completo (tutte le transazioni mai fatte)
/// 2. `utxo_set`: Stato corrente (solo output spendibili)
/// 
/// Il UTXO set è derivato dai blocchi, ma viene mantenuto
/// separatamente per performance (lookup O(1) invece di scansione blocchi).
#[derive(Debug)]
pub struct Blockchain {
    /// Catena di blocchi (storia completa)
    blocks: Vec<Block>,
    
    /// UTXO Set corrente (stato spendibile)
    utxo_set: UtxoSet,
}

impl Blockchain {
    /// Crea una nuova blockchain vuota
    pub fn new() -> Self {
        Self {
            blocks: Vec::new(),
            utxo_set: UtxoSet::new(),
        }
    }
    
    /// Crea una blockchain con genesis block
    pub fn with_genesis(genesis_block: Block) -> Self {
        let mut blockchain = Self::new();
        // Il genesis block non ha input, solo output (coinbase)
        // Applichiamo solo gli output al UTXO set
        for (index, output) in genesis_block.transactions.iter()
            .flat_map(|tx| tx.outputs.iter().enumerate())
        {
            let outpoint = OutPoint {
                txid: genesis_block.hash,
                index: index as u32,
            };
            blockchain.utxo_set.add(outpoint, output.clone());
        }
        
        blockchain.blocks.push(genesis_block);
        blockchain
    }
    
    /// Aggiunge un blocco alla chain
    /// 
    /// Passi:
    /// 1. Valida che il blocco sia valido
    /// 2. Valida tutte le transazioni
    /// 3. Applica le transazioni al UTXO set
    /// 4. Aggiunge il blocco allo storico
    pub fn add_block(&mut self, block: Block) -> Result<(), String> {
        // 1. Validazione blocco
        self.validate_block(&block)?;
        
        // 2. Valida tutte le transazioni
        for tx in &block.transactions {
            self.validate_transaction(tx)?;
        }
        
        // 3. Applica ogni transazione
        for tx in &block.transactions {
            self.apply_transaction(tx, block.hash)?;
        }
        
        // 4. Aggiungi blocco
        self.blocks.push(block);
        
        Ok(())
    }
    
    /// Valida un blocco prima di aggiungerlo
    /// 
    /// Controlli:
    /// - prev_block_hash corrisponde all'hash del blocco precedente
    /// - index è sequenziale
    /// - timestamp è ragionevole
    /// - hash è calcolato correttamente
    /// - firma valida
    fn validate_block(&self, block: &Block) -> Result<(), String> {
        // 1. Controlla che non sia il genesis (va aggiunto separatamente)
        if block.is_genesis() && !self.blocks.is_empty() {
            return Err("Cannot add genesis block to non-empty chain".to_string());
        }
        
        // 2. Se non è genesis, controlla prev_hash
        if !block.is_genesis() {
            let last_block = self.blocks.last()
                .ok_or("Cannot add block to empty chain")?;
            
            if block.prev_block_hash != last_block.hash {
                return Err(format!(
                    "Invalid prev_block_hash: expected {:?}, got {:?}",
                    last_block.hash, block.prev_block_hash
                ));
            }
            
            if block.index != last_block.index + 1 {
                return Err(format!(
                    "Invalid block index: expected {}, got {}",
                    last_block.index + 1, block.index
                ));
            }
        }
        
        // 3. Verifica che il blocco sia firmato
        if block.signature.is_none() {
            return Err("Block must be signed".to_string());
        }
        
        // 4. Verifica firma del blocco
        if !block.verify_signature() {
            return Err("Invalid block signature".to_string());
        }
        
        // 5. Verifica hash calcolato correttamente
        let calculated_hash = block.calculate_hash();
        if block.hash != calculated_hash {
            return Err("Block hash mismatch".to_string());
        }
        
        // 6. Almeno una transazione
        if block.transactions.is_empty() {
            return Err("Block must contain at least one transaction".to_string());
        }
        
        Ok(())
    }
    
    /// Valida una transazione prima di applicarla
    /// 
    /// Controlli:
    /// - Struttura valida (validate_structure)
    /// - Input esistono nel UTXO set
    /// - Firme valide per ogni input
    /// - Nessun double-spend all'interno della transazione
    /// - Public key hash corrisponde al recipient dell'UTXO speso
    fn validate_transaction(&self, tx: &Transaction) -> Result<(), String> {
        use crate::crypto::{BlockchainSigner, CryptoEncoding, BlockchainHasher};
        use crate::config::{SIGNER, HASHER};
        use std::collections::HashSet;
        
        // 1. Validazione struttura
        tx.validate_structure().map_err(|e| e.to_string())?;
        
        // Skip validation for coinbase
        if tx.is_coinbase() {
            return Ok(());
        }
        
        // 2. Verifica no duplicate inputs (double-spend interno)
        let mut seen_inputs = HashSet::new();
        for input in &tx.inputs {
            let outpoint = input.outpoint();
            if !seen_inputs.insert(outpoint.clone()) {
                return Err(format!("Duplicate input: {:?}", outpoint));
            }
        }
        
        // 3. Valida ogni input
        for (i, input) in tx.inputs.iter().enumerate() {
            let outpoint = input.outpoint();
            
            // 3a. UTXO esiste?
            let utxo = self.utxo_set.get(&outpoint)
                .ok_or(format!("UTXO not found: {:?}", outpoint))?;
            
            // 3b. Public key hash corrisponde al recipient?
            let pk_bytes = SIGNER.pk_to_bytes(&input.public_key);
            let pk_hash = HASHER.hash(&pk_bytes);
            let address: [u8; 20] = pk_hash[0..20].try_into()
                .map_err(|_| "Failed to derive address")?;
            
            if address != utxo.recipient {
                return Err(format!(
                    "Public key does not match UTXO recipient for input {}",
                    i
                ));
            }
            
            // 3c. Firma valida?
            let sighash = tx.sighash_for_input(i);
            if !SIGNER.verify(&input.public_key, &sighash, &input.signature) {
                return Err(format!("Invalid signature for input {}", i));
            }
        }
        
        Ok(())
    }
    
    /// Applica una transazione al UTXO set
    /// 
    /// Passi:
    /// 1. Spende tutti gli input (rimuove da UTXO set)
    /// 2. Crea tutti gli output (aggiunge al UTXO set)
    /// 3. Verifica che input sum >= output sum (solo per non-coinbase)
    fn apply_transaction(&mut self, tx: &Transaction, txid: HashOutput) -> Result<(), String> {
        let mut input_sum = 0u64;
        
        // 1. Spendi input (solo per non-coinbase)
        if !tx.is_coinbase() {
            for input in &tx.inputs {
                let outpoint = input.outpoint();
                
                match self.utxo_set.spend(&outpoint) {
                    Some(output) => {
                        input_sum += output.amount;
                    }
                    None => {
                        return Err(format!("UTXO not found: {:?}", outpoint));
                    }
                }
            }
        }
        
        // 2. Crea output
        for (index, output) in tx.outputs.iter().enumerate() {
            let outpoint = OutPoint {
                txid,
                index: index as u32,
            };
            self.utxo_set.add(outpoint, output.clone());
        }
        
        // 3. Verifica bilancio (solo per non-coinbase)
        if !tx.is_coinbase() {
            let output_sum = tx.total_output_value();
            if input_sum < output_sum {
                return Err(format!(
                    "Invalid transaction: inputs ({}) < outputs ({})",
                    input_sum, output_sum
                ));
            }
        }
        
        Ok(())
    }
    
    /// Accesso read-only al UTXO set
    pub fn utxo_set(&self) -> &UtxoSet {
        &self.utxo_set
    }
    
    /// Numero di blocchi nella chain
    pub fn height(&self) -> u32 {
        self.blocks.len() as u32
    }
    
    /// Ottiene un blocco per indice
    pub fn get_block(&self, index: u32) -> Option<&Block> {
        self.blocks.get(index as usize)
    }
    
    /// Ultimo blocco della chain
    pub fn last_block(&self) -> Option<&Block> {
        self.blocks.last()
    }
    
    /// Numero totale di UTXO spendibili
    pub fn utxo_count(&self) -> usize {
        self.utxo_set.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::crypto::BlockchainSigner;
    use crate::config::SIGNER;

    #[test]
    fn test_blockchain_creation() {
        let blockchain = Blockchain::new();
        assert_eq!(blockchain.height(), 0);
        assert_eq!(blockchain.utxo_count(), 0);
    }

    #[test]
    fn test_genesis_block() {
        // Genera una chiave per il test
        let private_key = SIGNER.generate();
        let public_key = SIGNER.get_public_key(&private_key);
        
        let genesis = Block::genesis(public_key);
        let blockchain = Blockchain::with_genesis(genesis);
        
        assert_eq!(blockchain.height(), 1);
        assert!(blockchain.last_block().is_some());
        assert!(blockchain.last_block().unwrap().is_genesis());
    }

    // TODO: Aggiungere test per add_block, apply_transaction
    
    #[test]
    fn test_transaction_validation() {
        use crate::transaction::{TxInput, TxOutput};
        use crate::crypto::{BlockchainHasher, CryptoEncoding};
        use crate::config::HASHER;
        
        // Setup: crea blockchain con genesis
        let priv_alice = SIGNER.generate();
        let pub_alice = SIGNER.get_public_key(&priv_alice);
        
        let mut blockchain = Blockchain::new();
        
        // Crea UTXO iniziale per Alice
        let utxo_output = TxOutput {
            amount: 100,
            recipient: {
                let pk_bytes = SIGNER.pk_to_bytes(&pub_alice);
                let hash = HASHER.hash(&pk_bytes);
                hash[0..20].try_into().unwrap()
            },
        };
        
        let outpoint = OutPoint {
            txid: [1u8; 32],
            index: 0,
        };
        
        blockchain.utxo_set.add(outpoint.clone(), utxo_output);
        
        // Crea transazione valida
        let mut tx = Transaction::new();
        
        // Prima aggiungi input (SENZA firma)
        tx.inputs.push(TxInput {
            previous_tx_id: outpoint.txid,
            output_index: outpoint.index,
            signature: SIGNER.sign(&priv_alice, &[0u8]).unwrap(), // Temporanea
            public_key: pub_alice,
        });
        
        // Poi aggiungi output
        tx.outputs.push(TxOutput {
            amount: 50,
            recipient: [2u8; 20],
        });
        
        // Ora calcola il sighash corretto e ri-firma
        let sighash = tx.sighash_for_input(0);
        let signature = SIGNER.sign(&priv_alice, &sighash).unwrap();
        
        // Aggiorna la firma
        tx.inputs[0].signature = signature;
        
        // Transazione deve essere valida
        assert!(blockchain.validate_transaction(&tx).is_ok());
    }
    
    #[test]
    fn test_block_validation_and_addition() {
        let priv_key = SIGNER.generate();
        let pub_key = SIGNER.get_public_key(&priv_key);
        
        // Crea blockchain con genesis
        let mut genesis = Block::genesis(pub_key);
        genesis.sign_and_finalize(&priv_key).unwrap();
        
        let mut blockchain = Blockchain::with_genesis(genesis.clone());
        
        // Crea coinbase per block2
        let mut coinbase = Transaction::new();
        coinbase.outputs.push(crate::transaction::TxOutput {
            amount: 50,
            recipient: {
                use crate::crypto::{BlockchainHasher, CryptoEncoding};
                use crate::config::HASHER;
                let pk_bytes = SIGNER.pk_to_bytes(&pub_key);
                let hash = HASHER.hash(&pk_bytes);
                hash[0..20].try_into().unwrap()
            },
        });
        
        // Crea secondo blocco
        let mut block2 = Block::new(
            1,
            genesis.hash,
            vec![coinbase],  // Almeno una transazione (coinbase)
            pub_key,
        );
        
        // Blocco non firmato -> errore
        assert!(blockchain.add_block(block2.clone()).is_err());
        
        // Firma il blocco
        block2.sign_and_finalize(&priv_key).unwrap();
        
        // Ora deve essere accettato
        assert!(blockchain.add_block(block2).is_ok());
        assert_eq!(blockchain.height(), 2);
    }
}
