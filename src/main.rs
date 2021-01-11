mod ames_cipher;

use crate::ames_cipher::ames::AmES;

/*
use cipher::generic_array::GenericArray;
use cipher::consts::U16;
use cipher::block::{BlockCipher, NewBlockCipher, Key};

use std::time::{Instant};
*/

use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

use hex_literal::hex;

type AmESCbc = Cbc<AmES, Pkcs7>;

fn main() {

    let key = hex!("91c3d48111ee4b2856eb31a6badb0a7f75a18dd26ba8ddaee03b6fe26343cb69");
    let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let plaintext = b"444444444444444444444444444444444444444444444444444444444";

    println!("Plaintext: {}", std::str::from_utf8(plaintext).unwrap());

    let cipher = AmESCbc::new_var(&key, &iv).unwrap();
    let ciphertext = cipher.encrypt_vec(plaintext);

    println!("Encrypted: {:?}", ciphertext);

    let cipher = AmESCbc::new_var(&key, &iv).unwrap();
    let decrypted_ciphertext = cipher.decrypt_vec(&ciphertext).unwrap();

    println!("Decrypted: {}", std::str::from_utf8(decrypted_ciphertext.as_slice()).unwrap());

    /*
    let data: [u8; 16] = [45, 38, 49, 76, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150];

    let mut block = GenericArray::<u8, U16>::clone_from_slice(&data);

    let ames = AmES::new(&Key::<AmES>::clone_from_slice(&key));

    println!("Before   : {:?}", block.as_slice());

    let start = Instant::now();
    ames.encrypt_block(& mut block);
    let duration = start.elapsed();

    println!("Encrypted: {:?}", block.as_slice());

    ames.decrypt_block(& mut block);

    println!("Decrypted: {:?}", block.as_slice());

    println!("Encryption duration: {:?}", duration);

    //println!("Hash: {}", scrypt_simple("hello bitch!", &ScryptParams::new(15, 18, 1)).expect("Bad scrypt"))

*/

}
