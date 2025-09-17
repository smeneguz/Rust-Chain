use chaincore::crypto::{hash_string, hash_to_hex};


fn main() {
    println!("Hello, world!");
    let m = "test hash function";
    let hash = hash_string(m);
    let hex_result = hash_to_hex(&hash);

    println!("hash: {:?}", hash);
    println!("hex hash: {}", hex_result); 

}
