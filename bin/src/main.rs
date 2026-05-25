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

    
    
    // iniziare a parlare dei layer di rete -> libp2p
    // programmazione asincrona in Rust
    // parallizzazioen tramite thread : std::thread per creare e gestirli
    /*
    message passin tra thread std::sync::mpsc sistema di pubsub
    vantaggioso perchè non dobbiamo preoccuparci chi c'è dall'altra parte

    spesso è importante quando passi dal thread principale a un altro thread passare delle variabile
    ma c'è da attenzionare l'ownership
    shared state tramite std:sync e mutex .. thread::spawn(move || ...) muove i dati che inseriamo se vogliamo invece condividere
    senza passare usiamo Arc condivisione in lettura, creiamo, cloniamo e passiamo il clone ma se vogliamo
    anche avere una scrittura usiamo anche Mutex che è una struttur che blocca accesso a una risorsa fintanto
    che la risorsa non viene aquisita
    arc condivide tra thread separati e mutex atomicità

    creare arc dentro il quale inizializziamo un mutex e quando cloniamo questo arc il mutex conterrà il cone 
    

    trait Send e Sync quando marcata come Send una struct: questo dato può essere trasferito in modo sicuro tra un thread e un altro con move
    Sync inveece dice che il dato possa essere condiviso tra più thread in maniera sicura quindi posso metterlo in un Arc con Arc

    rc non treatd safe usa 
    cell non thread safe usa


    Async Rust
    async / await codice che è asincrono ma che appare come codice sincrono, basato al concetto di futures (promise in javascript) , struttura che 
    conterrà al suo interno il risultato dell'operazione una volta che questa sarà terminata

    in più rust non mette all'interno del linguaggio il run time.. te lo devi portare tu esempio con Tokio 
    operazioni che richiedono tempo per terminare come operazioni I/O, rete ... differenza tra multi thread e async await
    multi thread -> più thread che eseguono codice in parallelo
    async await -> un singolo thread che esegue più operazioni apparentemente in parallelo che risolve il problema di context switching tra thread cioè spiegato più semplicemente
    quando il sistema operativo deve passare l'esecuzione da un thread a un altro deve salvare lo stato del thread corrente e caricare lo stato del thread successivo
    questo costa in termini di performance
    con async await invece abbiamo un singolo thread che esegue più operazioni e quando una operazione richiede tempo per terminare (esempio attesa di risposta da rete)
    invece di bloccare il thread, l'operazione viene messa in attesa e il thread può eseguire altre operazioni nel frattempo
    quando l'operazione in attesa è pronta, viene notificata al thread che può riprendere l'esecuzione della stessa

    implementazione di un runtime asincorno prevede l'uso di un event loop che gestisce le operazioni asincrone
    questo non è implementato nel linguaggio rust ma tramite librerie esterne come tokio o async-std

    marcatore #[tokio::main] per implementare trait asincroni
    codice asincrono vs thread based event web meglio async await per operazioni I/O e rete, thread based per operazioni CPU intensive

    multi thread con tokio -> combinazione di entrambi, tokio permette di eseguire operazioni asincrone su più thread, creando un pool di thread per eseguire le operazioni asincrone in parallelo
    tokio::spawn(async {
        // codice asincrono qui dentro
    }); qui si può fare handle.await? per aspettare il completamento

    sync and send anche per async and await, se una struct è Send può essere spostata tra thread anche in contesto asincrono, se è Sync può essere condivisa tra thread anche in contesto asincrono
     */



}