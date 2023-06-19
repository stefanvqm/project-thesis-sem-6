#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(non_camel_case_types)]

use super::{AES, Blocksize};


pub struct AES_CBC {
    iv: [u8; 16],
    cipher: AES,
    last_block: [u8; 16],
    use_iv: bool,
}

impl AES_CBC {
    pub fn new(key: &[u8], blocksize: Blocksize) -> Self {
        Self {
            iv: [0; 16],
            cipher: AES::new(key, blocksize),
            last_block: [0; 16],
            use_iv: true,
        }
    }

    pub fn encrypt(&mut self, input: &[u8]) -> Vec<u8> {
        self.iv = self.initialization_vector();

        let mut block: [u8; 16] = Default::default();
        let mut iterator: usize = 0;

        let mut output: Vec<u8> = Default::default();

        for b in input.iter() {
            block[iterator] = *b;
            iterator += 1;

            if iterator >= 16 {
                iterator = 0;
                output.append(self.cipher(&mut block).to_vec().as_mut());
            }
        }

        if iterator != 0 {
            output.append(self.cipher(&mut block).to_vec().as_mut());
        }

        self.use_iv = true;
        self.last_block = [0; 16];

        output
    }

    fn cipher(&mut self, block: &mut [u8; 16]) -> [u8; 16] {
        let cipher: [u8; 16];

        let to_encrypt: [u8; 16];

        if self.use_iv {
            self.use_iv = false;
            to_encrypt = AES_CBC::xor_arrays(*block, self.iv);
        } else {
            to_encrypt = AES_CBC::xor_arrays(*block, self.last_block);
        }

        cipher = self.cipher.cipher(to_encrypt);

        self.last_block = cipher;
        cipher
    }

    pub fn decrypt(&mut self, input: &[u8]) -> Vec<u8> {
        self.iv = self.initialization_vector();

        let mut block: [u8; 16] = Default::default();
        let mut iterator: usize = 0;

        let mut output: Vec<u8> = Default::default();

        for b in input.iter() {
            block[iterator] = *b;
            iterator += 1;

            if iterator >= 16 {
                iterator = 0;
                output.append(self.inv_cipher(&mut block).to_vec().as_mut());
            }
        }

        if iterator != 0 {
            output.append(self.cipher(&mut block).to_vec().as_mut());
        }

        self.use_iv = true;
        self.last_block = [0; 16];

        output
    }

    fn inv_cipher(&mut self, block: &mut [u8; 16]) -> [u8; 16] {
        let plaintext: [u8; 16];
        let decrypted: [u8; 16] = self.cipher.inv_cipher(*block);

        if self.use_iv {
            self.use_iv = false;
            plaintext = AES_CBC::xor_arrays(decrypted, self.iv);
        } else {
            plaintext = AES_CBC::xor_arrays(decrypted, self.last_block);
        }

        self.last_block = *block;
        plaintext
    }

    fn initialization_vector(&mut self) -> [u8; 16] {
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
    }

    fn xor_arrays(x: [u8; 16], y: [u8; 16]) -> [u8; 16] {
        let mut z: [u8; 16] = Default::default();

        for i in 0..16 {
            z[i] = x[i] ^ y[i];
        }

        z
    }
}

#[cfg(test)]
mod tests {
    use super::{Blocksize, AES_CBC};
    
    #[test]
    fn encrypt() {  
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

        assert_eq!(decrypted, input.to_vec());
    }
}
