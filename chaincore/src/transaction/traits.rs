pub trait TransactionModel {
    type Id;
    type Error;

    fn compute_id(&self) -> Self::Id;
    fn is_valid(&self) -> Result<bool, Self::Error>;
    fn to_bytes(&self) -> Vec<u8>; 
}

pub trait TransactionOutputModel {
    fn is_owned_by(&self, owner: &[u8]) -> bool;
    fn value(&self) -> u64;
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait TransactionInputModel {
    type Error;

    fn sign(&mut self, private_key: &[u8]) -> Result<(),Self::Error>;
    fn verify_signature(&self) -> bool;
    fn to_bytes(&self) -> Vec<u8>;
    fn previous_transaction_id(&self) -> &[u8];
    fn output_index(&self) -> usize;

}