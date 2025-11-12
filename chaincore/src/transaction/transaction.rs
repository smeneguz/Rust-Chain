use crate::crypto::crypto::BlockchainHasher;
use crate::config::{Signature, PublicKey, HashOutput};

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
}

pub trait TxCodec {
    fn ser_no_witness(&self) -> Vec<u8>;
    fn ser_with_witness(&self) -> Vec<u8>;
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

pub trait UtxoView {
    type TxOutRef;
    fn lookup(&self, outpoint: &OutPoint) -> Option<Self::TxOutRef>;
}
