mod ames_cipher;

use crate::ames_cipher::ames::AmES;

use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

use hex_literal::hex;

use std::time::{Instant};

type AmESCbc = Cbc<AmES, Pkcs7>;

fn main() {

    let key = hex!("91c3d48111ee4b2856eb31a6badb0a7f75a18dd26ba8ddaee03b6fe26343cb69");
    let iv = hex!("6adea10c58f0741eddd0008726f99089");
    let plaintext = ['h' as u8; 100000];

    println!("Plaintext: {}", std::str::from_utf8(&plaintext).unwrap());

    let cipher = AmESCbc::new_var(&key, &iv).unwrap();

    let start = Instant::now();
    let ciphertext = cipher.encrypt_vec(&plaintext);
    println!("Encrypted in {:?}", start.elapsed());

    println!("Encrypted: {:?}", ciphertext);

    let cipher = AmESCbc::new_var(&key, &iv).unwrap();

    let start = Instant::now();
    let decrypted_ciphertext = cipher.decrypt_vec(&ciphertext).unwrap();
    println!("Decrypted in {:?}", start.elapsed());

    println!("Decrypted: {}", std::str::from_utf8(decrypted_ciphertext.as_slice()).unwrap());

}
