use crate::crypto::crypto::BlockchainHasher;
use crate::config::{Signature, PublicKey, HashOutput};
use crate::config::HASHER;
use crate::crypto::CryptoEncoding;
use crate::config::SIGNER;


#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OutPoint {
    pub txid: HashOutput,
    pub index: u32,
}

#[derive(Debug, Clone)]
pub struct TxInput {
    pub previous_tx_id: HashOutput,
    pub output_index: u32,
    pub signature: Signature,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone)]
pub struct TxOutput {
    pub amount: u64,
    pub recipient: [u8; 20],
}

#[derive(Debug, Clone)]
pub struct Transaction {
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
}

impl TxInput {
    pub fn outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.previous_tx_id,
            index: self.output_index,
        }
    }
}

impl Transaction {
    pub fn new() -> Self {
        Self {
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }
    
    pub fn total_output_value(&self) -> u64 {
        self.outputs.iter().map(|o| o.amount).sum()
    }
    
    // Verifica se questa è una coinbase transaction (no inputs)
    pub fn is_coinbase(&self) -> bool {
        self.inputs.is_empty()
    }
    

    pub fn validate_structure(&self) -> Result<(), &'static str> {
        // Almeno un output richiesto
        if self.outputs.is_empty() {
            return Err("Transaction must have at least one output");
        }
        
        // Coinbase: zero inputs
        // Regular: almeno un input
        if !self.is_coinbase() && self.inputs.is_empty() {
            return Err("Non-coinbase transaction must have at least one input");
        }
        
        // Tutti gli output devono avere amount > 0
        for output in &self.outputs {
            if output.amount == 0 {
                return Err("Output amount must be greater than zero");
            }
        }

        // fare check su signature
        
        // Verifica overflow nella somma
        let mut total: u64 = 0;
        for output in &self.outputs {
            total = total.checked_add(output.amount)
                .ok_or("Output amounts overflow")?;
        }
        
        Ok(())
    }
    
    // Calcola il TXID (transaction ID) usando l'hasher configurato
    pub fn txid(&self) -> HashOutput {
        StandardSighash::txid(&HASHER, self)
    }
    
    // Calcola l'hash da firmare per un input specifico
    pub fn sighash_for_input(&self, input_index: usize) -> HashOutput {
        StandardSighash::for_input(&HASHER, self, input_index, 0, &[], ())
    }
}

pub trait TxCodec {
    fn ser_no_witness(&self) -> Vec<u8>;
    fn ser_with_witness(&self) -> Vec<u8>;
}

// Implementazione serializzazione Transaction
impl TxCodec for Transaction {
    // Serializzazione senza firme (per calcolo TXID)
    fn ser_no_witness(&self) -> Vec<u8> {

        let mut bytes = Vec::new();
        
        // Numero di inputs
        bytes.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        
        // Serializza ogni input (SENZA signature)
        for input in &self.inputs {
            bytes.extend_from_slice(&input.previous_tx_id);
            bytes.extend_from_slice(&input.output_index.to_le_bytes());
            bytes.extend_from_slice(&SIGNER.pk_to_bytes(&input.public_key));
        }
        
        // Numero di outputs
        bytes.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        
        // Serializza ogni output
        for output in &self.outputs {
            bytes.extend_from_slice(&output.amount.to_le_bytes());
            bytes.extend_from_slice(&output.recipient);
        }
        
        bytes
    }
    
    // Serializzazione completa (CON firme, per trasmissione network)
    fn ser_with_witness(&self) -> Vec<u8> {
        
        let mut bytes = Vec::new();
        
        // Numero di inputs
        bytes.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        
        // Serializza ogni input (CON signature)
        for input in &self.inputs {
            bytes.extend_from_slice(&input.previous_tx_id);
            bytes.extend_from_slice(&input.output_index.to_le_bytes());
            
            let sig_bytes = SIGNER.sig_to_bytes(input.signature.clone());
            bytes.extend_from_slice(&(sig_bytes.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&sig_bytes);
            
            bytes.extend_from_slice(&SIGNER.pk_to_bytes(&input.public_key));
        }
        
        // Numero di outputs
        bytes.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        
        // Serializza ogni output
        for output in &self.outputs {
            bytes.extend_from_slice(&output.amount.to_le_bytes());
            bytes.extend_from_slice(&output.recipient);
        }
        
        bytes
    }
}

pub trait Sighash<H: BlockchainHasher> {
    type Flags: Copy;
    fn txid(hasher: &H, tx: &Transaction) -> H::Output;
    fn wtxid(hasher: &H, tx: &Transaction) -> H::Output;
    fn for_input(
        hasher: &H,
        tx: &Transaction,
        input_index: usize,
        prev_value: u64,
        prev_script_pubkey: &[u8],
        flags: Self::Flags,
    ) -> H::Output;
}

pub struct StandardSighash;

impl<H: BlockchainHasher> Sighash<H> for StandardSighash {
    type Flags = (); // Nessun flag per ora
    
    fn txid(hasher: &H, tx: &Transaction) -> H::Output {
        let data = tx.ser_no_witness();
        hasher.hash(&data)
    }
    

    fn wtxid(hasher: &H, tx: &Transaction) -> H::Output {
        let data = tx.ser_with_witness();
        hasher.hash(&data)
    }
    
    // Calcola signature hash per un input specifico 
    // Questo hash viene firmato dal possessore della chiave privata
    // corrispondente all'output che si sta spendendo
    fn for_input(
        hasher: &H,
        tx: &Transaction,
        input_index: usize,
        _prev_value: u64, // Non usato in questa versione semplice
        _prev_script_pubkey: &[u8], // Non usato in questa versione semplice
        _flags: Self::Flags,
    ) -> H::Output {

        let mut bytes = Vec::new();
        
        // Numero di inputs
        bytes.extend_from_slice(&(tx.inputs.len() as u32).to_le_bytes());
        
        // Serializza inputs: includi public_key SOLO per l'input che stiamo firmando
        for (i, input) in tx.inputs.iter().enumerate() {
            bytes.extend_from_slice(&input.previous_tx_id);
            bytes.extend_from_slice(&input.output_index.to_le_bytes());
            
            // Includi public_key SOLO per l'input corrente
            if i == input_index {
                bytes.extend_from_slice(&SIGNER.pk_to_bytes(&input.public_key));
            }
        }
        
        // Numero di outputs
        bytes.extend_from_slice(&(tx.outputs.len() as u32).to_le_bytes());
        
        // Serializza tutti gli outputs
        for output in &tx.outputs {
            bytes.extend_from_slice(&output.amount.to_le_bytes());
            bytes.extend_from_slice(&output.recipient);
        }
        
        hasher.hash(&bytes)
    }
}

pub trait UtxoView {
    type TxOutRef;
    fn lookup(&self, outpoint: &OutPoint) -> Option<Self::TxOutRef>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::BlockchainSigner;
    use crate::config::SIGNER;
    
    #[test]
    fn test_transaction_validation() {
        let mut tx = Transaction::new();
        
        // Transaction vuota -> errore
        assert!(tx.validate_structure().is_err());
        
        // Aggiungi output
        tx.outputs.push(TxOutput {
            amount: 100,
            recipient: [1u8; 20],
        });
        
        // Coinbase valid (no inputs, 1 output)
        assert!(tx.validate_structure().is_ok());
        
        // Regular transaction senza inputs -> errore
        let priv_key = SIGNER.generate();
        let pub_key = SIGNER.get_public_key(&priv_key);
        
        tx.inputs.push(TxInput {
            previous_tx_id: [0u8; 32],
            output_index: 0,
            signature: SIGNER.sign(&priv_key, &[0u8]).unwrap(),
            public_key: pub_key,
        });
        
        // Ora è valida
        assert!(tx.validate_structure().is_ok());
    }
    
    #[test]
    fn test_txid_calculation() {
        let priv_key = SIGNER.generate();
        let pub_key = SIGNER.get_public_key(&priv_key);
        
        let mut tx = Transaction::new();
        tx.outputs.push(TxOutput {
            amount: 50,
            recipient: [2u8; 20],
        });
        
        tx.inputs.push(TxInput {
            previous_tx_id: [1u8; 32],
            output_index: 0,
            signature: SIGNER.sign(&priv_key, &[0u8]).unwrap(),
            public_key: pub_key,
        });
        
        // Calcola TXID
        let txid1 = tx.txid();
        let txid2 = tx.txid();
        
        // TXID deve essere deterministico
        assert_eq!(txid1, txid2);
        
        // TXID non deve essere zero
        assert_ne!(txid1, [0u8; 32]);
    }
    
    #[test]
    fn test_serialization_deterministic() {
        let priv_key = SIGNER.generate();
        let pub_key = SIGNER.get_public_key(&priv_key);
        
        let mut tx = Transaction::new();
        tx.outputs.push(TxOutput {
            amount: 100,
            recipient: [3u8; 20],
        });
        
        tx.inputs.push(TxInput {
            previous_tx_id: [2u8; 32],
            output_index: 1,
            signature: SIGNER.sign(&priv_key, &[0u8]).unwrap(),
            public_key: pub_key,
        });
        
        // Serializzazione senza witness deve essere deterministica
        let ser1 = tx.ser_no_witness();
        let ser2 = tx.ser_no_witness();
        assert_eq!(ser1, ser2);
        
        // Serializzazione con witness deve essere deterministica
        let ser_w1 = tx.ser_with_witness();
        let ser_w2 = tx.ser_with_witness();
        assert_eq!(ser_w1, ser_w2);
        
        // Con witness deve essere più lungo (include firme)
        assert!(ser_w1.len() > ser1.len());
    }
}
