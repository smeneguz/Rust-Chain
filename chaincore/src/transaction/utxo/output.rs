use crate::transaction::traits::TransactionOutputModel;

pub fn create_output(value: u64, recipient_pubkey: &[u8; 32]) -> UtxoOutput {
    UtxoOutput::new(value, recipient_pubkey)
}

/// Verifica se un output appartiene a un proprietario
pub fn is_output_owned_by(output: &UtxoOutput, owner_pubkey: &[u8; 32]) -> bool {
    output.is_owned_by(owner_pubkey)
}

/// Serializza un output in bytes
pub fn output_to_bytes(output: &UtxoOutput) -> Vec<u8> {
    output.to_bytes()
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UtxoOutput {
    value: u64,
    
    // Chiave pubblica Ed25519 del destinatario (32 bytes fixed)
    recipient_pubkey: [u8; 32],
}

impl UtxoOutput {
    pub fn new(value: u64, recipient_pubkey: &[u8;32]) -> Self{
        Self{
            value: value,
            recipient_pubkey: *recipient_pubkey // oppure copy array con *recipient_publkey ??
        }
    }

    
    /// Ritorna il valore dell'output
    pub fn value(&self) -> u64 {
        self.value
    }
    
    /// Ritorna la chiave pubblica del proprietario
    pub fn recipient_pubkey(&self) -> &[u8; 32] {
        &self.recipient_pubkey
    }
}


impl TransactionOutputModel for UtxoOutput {

    fn is_owned_by(&self, owner: &[u8]) -> bool {
        // Verifica che owner sia esattamente 32 bytes 
        // questo va cambiato nel caso in cui si va a cambiare firma e lunghezza
        if owner.len() != 32 {
            return false;
        }
        
        // Confronta con recipient_pubkey
        self.recipient_pubkey.as_slice() == owner
    }
    
    /// Ritorna il valore dell'output
    fn value(&self) -> u64 {
        self.value
    }
    

    // Formato: [value (8 bytes)] + [pubkey (32 bytes)]
    // Totale: 40 bytes fissi
    // Formato deterministico per hashing consistente
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(40);  // Pre-allocate: 8 + 32
        
        // 1. Value (8 bytes, little-endian)
        bytes.extend_from_slice(&self.value.to_le_bytes());
        
        // 2. Public key (32 bytes)
        bytes.extend_from_slice(&self.recipient_pubkey);
        
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_create_output() {
        let pubkey = [1u8; 32];
        let output = UtxoOutput::new(100, &pubkey);
        
        assert_eq!(output.value(), 100);
        assert_eq!(output.recipient_pubkey(), &pubkey);
    }
    
    #[test]
    fn test_is_owned_by() {
        let alice_pubkey = [1u8; 32];
        let bob_pubkey = [2u8; 32];
        
        let output = UtxoOutput::new(50, &alice_pubkey);
        
        // Alice possiede l'output
        assert!(output.is_owned_by(&alice_pubkey));
        
        // Bob NON possiede l'output
        assert!(!output.is_owned_by(&bob_pubkey));
    }
    
    #[test]
    fn test_is_owned_by_wrong_length() {
        let pubkey = [1u8; 32];
        let output = UtxoOutput::new(50, &pubkey);
        
        // Chiave con lunghezza sbagliata
        let wrong_key = [1u8; 16];
        assert!(!output.is_owned_by(&wrong_key));
    }
    
    #[test]
    fn test_to_bytes() {
        let pubkey = [42u8; 32];
        let output = UtxoOutput::new(100, &pubkey);
        let bytes = output.to_bytes();
        
        // Lunghezza fissa: 8 (value) + 32 (pubkey) = 40 bytes
        assert_eq!(bytes.len(), 40);
        
        // Verifica value (primi 8 bytes)
        let value_bytes = &bytes[0..8];
        assert_eq!(u64::from_le_bytes(value_bytes.try_into().unwrap()), 100);
        
        // Verifica pubkey (ultimi 32 bytes)
        let pubkey_bytes = &bytes[8..40];
        assert_eq!(pubkey_bytes, &pubkey);
    }
    
    #[test]
    fn test_helper_functions() {
        let pubkey = [1u8; 32];
        
        // Test create_output
        let output = create_output(100, &pubkey);
        assert_eq!(output.value(), 100);
        
        // Test is_output_owned_by
        assert!(is_output_owned_by(&output, &pubkey));
        
        // Test output_to_bytes
        let bytes = output_to_bytes(&output);
        assert_eq!(bytes.len(), 40);
    }
    
    #[test]
    fn test_deterministic_serialization() {
        let pubkey = [7u8; 32];
        let output1 = UtxoOutput::new(100, &pubkey);
        let output2 = UtxoOutput::new(100, &pubkey);
        
        // Stessi dati = stesso hash
        assert_eq!(output1.to_bytes(), output2.to_bytes());
    }
}