/* Author: Stefan Goetz, 2023
Warranty Disclaimer: the software is provided "as is" without any warranties or conditions.
Implementation according to https://datatracker.ietf.org/doc/html/rfc6234
*/


use super::HashType;
use super::Sha256;
use super::Sha512;

pub struct HMAC {
    output: Vec<u8>,
    b: u32,
    l: u32,
    hash_type: HashType
}

impl HMAC {
    pub fn new(htype: HashType) -> Self {
        Self {
            output: Default::default(),
            b: 0,
            l: 0,
            hash_type: htype
        }
    }
    
    pub fn digest(&mut self, k: & [u8], message: &[u8]) -> &mut Vec<u8> {
        self.b_and_l_vars();

        let key: Vec<u8> = self.key_management(&k);

        let ipad: Vec<u8>;
        let opad: Vec<u8>;

        (ipad, opad) = self.pad();

        let mut a: Vec<u8> = self.xor(&key, &opad);
        let mut b: Vec<u8> = self.xor(&key, &ipad);

        b.append(&mut message.to_vec());

        let inner_hash: Vec<u8> = self.hash(&b);

        a.append(&mut inner_hash.to_vec());

        self.output = self.hash(a.as_slice());

        &mut self.output
    }

    pub fn string(&self) -> String {
        self.output.iter().map(|x: &u8| format!("{:02x}", x)).collect::<String>()
    }

    fn hash(&self, str: &[u8]) -> Vec<u8> {
        match self.hash_type {
            HashType::Sha256Type => {
                let mut sha: Sha256 = Sha256::new();
                sha.digest(&str).to_vec()
            }
            HashType::Sha512Type => {
                let mut sha: Sha512 = Sha512::new();
                sha.digest(&str).to_vec()
            }
        }
    }

    fn b_and_l_vars(&mut self) {
        match self.hash_type {
            HashType::Sha256Type => {
                self.b = 64;
                self.l = 32;
            }
            HashType::Sha512Type => {
                self.b = 128;
                self.l = 64;
            }
        }
    }

    fn key_management(&self, k: & [u8]) -> Vec<u8> {
        let mut key: Vec<u8>;

        if k.len() > self.b as usize {
            key = self.hash(&k);
        } else {
            key = k.to_vec();
        }
        
        for _ in 0..(self.b as usize - key.len()) {
            key.push(0x00);
        }

        key
    }

    fn pad(&self) -> (Vec<u8>, Vec<u8>) {
        let mut ipad: Vec<u8> = Default::default();
        let mut opad: Vec<u8> = Default::default();

        for _ in 0..self.b {
            ipad.push(0x36);
            opad.push(0x5c);
        }

        (ipad, opad)
    }

    fn xor(&self, a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
        let mut c: Vec<u8> = Default::default();
        for i in 0..(self.b as usize) {
            c.push(a[i] ^ b[i]);
        }
        c
    }
}


#[cfg(test)]
mod tests {
    use crate::hash::HMAC;
    use crate::hash::HashType;
    #[test]
    fn hmac_test() {
    // Following test values will use test inputs from 
    // https://www.rfc-editor.org/rfc/rfc4231#section-4.1
        fn check_hmac_sha_256(message: &[u8], key: &[u8], correct_value: &str) {
            let mut hmac_sha256 = HMAC::new(HashType::Sha256Type);
            hmac_sha256.digest(key, message);

            assert_eq!(hmac_sha256.string(), correct_value);
        }

        check_hmac_sha_256(
            "Hi There".as_bytes(),
            [0x0b; 20].as_slice(), 
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        );
        check_hmac_sha_256(
            "what do ya want for nothing?".as_bytes(), 
            "Jefe".as_bytes(), 
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        );
        
        check_hmac_sha_256(
            [0xdd; 50].as_slice(), 
            [0xaa; 20].as_slice(), 
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        );
        check_hmac_sha_256(
            "Test With Truncation".as_bytes(),
            [0x0c; 20].as_slice(),
            "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5",
        );
        check_hmac_sha_256(
            "Test Using Larger Than Block-Size Key - Hash Key First".as_bytes(),
            [0xaa; 131].as_slice(),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        );
        check_hmac_sha_256(
            "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".as_bytes(),
            [0xaa; 131].as_slice(),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        );
    }
}