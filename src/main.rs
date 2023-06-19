/* Author: Stefan Goetz, 2023
Warranty Disclaimer: the software is provided "as is" without any warranties or conditions.
*/

#![allow(dead_code)]
#![allow(unused_variables)]

pub mod hash;
pub mod crypto;
pub mod utils;

use hash::{Sha256, Sha512, HMAC, HashType};
use crypto::{AES_CBC, Blocksize, ECDH, scalarmult};

fn main() {
    hash_example();
    hmac_example();
    ecc_example();
    aes_example();
}

fn hash_example() {
    let mut sha256: Sha256 = Sha256::new();
    let res256: [u8; 32] = sha256.digest("abc".as_bytes());

    let mut sha512: Sha512 = Sha512::new();
    let res512: [u8; 64] = sha512.digest("abc".as_bytes());
}

fn hmac_example() {
    let k: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
    ];

    let message: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
    ];

    let mut hmac: HMAC = HMAC::new(HashType::Sha256Type);
    let res: &mut Vec<u8> = hmac.digest(&k.as_slice(), &message.as_slice());
}

fn ecc_example() {
    let alice_private_key: [u8; 32] = [0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a];
    let alice_public_key: [u8; 32] = [0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a];
    
    let mut ecdh: ECDH = ECDH::new();
    ecdh.gen_key_pair();

    let key1: [u8; 32] = scalarmult(&ecdh.pub_key, &alice_private_key);
    let key2: [u8; 32] = ecdh.symmetric_key(&alice_public_key);
}

fn aes_example() {
    let key: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    let mut aes_128_cbc: AES_CBC = AES_CBC::new(key.as_slice(), Blocksize::B128);
    let input: [u8; 64] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    ];

    let encrypted: Vec<u8> = aes_128_cbc.encrypt(input.as_slice());
    let decrypted: Vec<u8> = aes_128_cbc.decrypt(encrypted.as_slice());
}

// // // // // // // // // // // // // // // 
// // // // // // // // // // // // // // // 
// // // // // // // // // // // // // // // 
// // // // // // // // // // // // // // // 
// // // // // // // // // // // // // // // 
// // // // // // // // // // // // // // //