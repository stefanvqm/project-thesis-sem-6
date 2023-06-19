#![allow(dead_code)]
#![allow(unused_variables)]

use super::Curve;

use crate::hash::Sha512;

pub struct ECDSA {
    curve: Curve,
    secret_scalar: [u8; 32]
}

impl ECDSA {
    pub fn new(secret_key: [u8; 32]) -> Self {
        Self { 
            curve: Curve::twisted_edwards(),
            secret_scalar: self.compute_secret_scalar(&secret_key),
        }
    }

    fn compute_secret_scalar(&self, secret_key: &[u8; 32]) -> [u8; 32] {
        secret_key
    }

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
    #[test] 
    fn test() {
        todo!()
    }
}