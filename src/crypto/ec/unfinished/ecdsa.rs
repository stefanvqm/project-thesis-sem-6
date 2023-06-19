#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

use super::{Curve};
use super::{scalarmult, scalarmult_64bytes, pack25519};

use crate::hash::Sha512;

pub struct ECDSA {
    curve: Curve,
    s: [u8; 32],
    h: [u8; 64],
    big_a: [u8; 32],
    prefix: [u8; 32],
    // nonce: [u8; 64],
    // commitment: [u8; 32],
    // challenge: [u8; 64],
}

impl ECDSA {
    pub fn new() -> Self {
        Self {
            curve: Curve::twisted_edwards(),
            s: [0; 32],
            h: [0; 64],
            big_a: [0; 32],
            prefix: [0; 32],
            // nonce: [0; 64],
            // commitment: [0; 32],
            // challenge: [0; 64],
        }
    }

    pub fn compute(&mut self, secret_key: &[u8; 32]) -> () {
        self.compute_public_key(secret_key);
        // self.compute_nonce(&message);
        // self.compute_commitment();
        // self.compute_challenge(&message); , message: &[u8]
    }

    fn compute_public_key(&mut self, secret_key: &[u8; 32]) -> () {
        let mut key_hash: Sha512 = Sha512::new();
        self.h = key_hash.digest(&secret_key.as_slice());

        for i in 0..64 {
            if i < 32 {
                self.s[i] = self.h[i];
            } else {
                self.prefix[i-32] = self.h[i];
            }
        }

        self.s[0] &= 248;
        self.s[31] &= 127;
        self.s[31] |= 64;
        
        let mut big_a_x: [u8; 32] = scalarmult(&pack25519(&mut self.curve.g.x), &self.s);
        let mut big_a_y: [u8; 32] = scalarmult(&pack25519(&mut self.curve.g.y), &self.s);

        // big_a_y[31] &= 254;
        // let w: u8 = big_a_x[0] &= 128;

        println!("big_a_y {:?}", big_a_y);
        println!("big_a_x {:?}", big_a_x);
    }

    // fn compute_nonce(&mut self, message: &[u8]) {
    //     let mut sha512: Sha512 = Sha512::new();
    //     self.nonce = sha512.digest([message, self.prefix.as_slice()].concat().as_slice());
    // }

    // fn compute_commitment(&mut self) {
    //     self.commitment = scalarmult_64bytes(&self.curve.b, &self.nonce);
    // }

    // fn compute_challenge(&mut self, message: &[u8]) {
    //     let mut sha512: Sha512 = Sha512::new();
    //     let to_hash: &[u8] = [self.nonce.as_slice(), self.public_key.as_slice(), self.]
    //     self.nonce = sha512.digest(&to_hash);
    // }

    // #[warn(unreachable_code)]
    // pub fn sign(message: &[u8]) {
    //     !todo!();
    // }

    // #[warn(unreachable_code)]
    // pub fn verify() {
    //     !todo!();
    // }
}

#[cfg(test)]
mod tests {
    use super::ECDSA;

    #[test] 
    fn test_public_key() {

        let secret_key: [u8; 32] = [0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60];
        
        let expected_public_key: [u8; 32] = [0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a]; 
        println!("expected_public_key {:?}", expected_public_key);
        let mut ecdsa: ECDSA = ECDSA::new();
        ecdsa.compute(&secret_key);
    }
}