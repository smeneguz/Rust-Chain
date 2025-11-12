use chaincore::crypto::{hash_string, hash_to_hex};
use chaincore::crypto::{sign_message, generate_keypair, verify_signature, get_public_key};
use chaincore::BlockchainSigner;

// Usa il signer di default dalla configurazione
use chaincore::SIGNER;


fn main() {

    println!("Hello, world!");
    let m = "test hash function";
    let hash = hash_string(m);
    let hex_result = hash_to_hex(&hash);

    println!("hash: {:?}", hash);
    println!("hex hash: {}", hex_result); 

    let message = b"test per firma digitale";
    let my_keys = generate_keypair();
    let pub_key = get_public_key(&my_keys);
    let sign_message = sign_message(&my_keys, message);
    println!("sign_message test {}", sign_message);

    let try_verify = verify_signature(&sign_message, &pub_key, message);

    println!("test verifica: {}", try_verify);

    // test con trait - USA SIGNER dalla configurazione
    let m2 = b"test implementazione tramite trait agnostico riguardo l'algoritmo di firma digitale";
    let my_key = SIGNER.generate();
    let pub_key = SIGNER.get_public_key(&my_key);
    println!("pub key con trait {:#?}", &pub_key);

    let sign_m = SIGNER.sign(&my_key, m2).unwrap();

    println!("vediamo cosa c'è dentro alla sign {:?}", &sign_m);

    let is_valid_sign = SIGNER.verify(&pub_key, m2, &sign_m);

    println!("boool vediamo {}", is_valid_sign);
    
    if !is_valid_sign {
        panic!("mannaggia");
    }

    
    
}