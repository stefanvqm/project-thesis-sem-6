/* Author: Stefan Goetz, 2023
Warranty Disclaimer: the software is provided "as is" without any warranties or conditions.
Implementation according to https://datatracker.ietf.org/doc/html/rfc6234
*/

fn rotr(x: u64, n: u64) -> u64 {
    x.rotate_right(n.try_into().unwrap())
}

fn shr(x: u64, n: u64) -> u64 {
    x >> n
}

fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ ((!x) & z)
}

fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn bsig0(x: u64) -> u64 {
    rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39)
}

fn bsig1(x: u64) -> u64 {
    rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41)
}

fn ssig0(x: u64) -> u64 {
    rotr(x, 1) ^ rotr(x, 8) ^ shr(x, 7)
}

fn ssig1(x: u64) -> u64 {
    rotr(x, 19) ^ rotr(x, 61) ^ shr(x, 6)
}

fn add(x: u64, y: u64) -> u64 {
    x.wrapping_add(y)
}

pub struct Sha512 {
    block: [u8; 128],
    block_length: usize,
    additional_padding_block: [u8; 128],
    output: [u64; 8],
    input_length: u128,
}

impl Sha512 {
    pub fn new() -> Self {
        Self {
            block: [0; 128],
            block_length: 0,
            additional_padding_block: [0; 128],
            output: [
                0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
            ],
            input_length: 0,
        }
    }

    pub fn digest(&mut self, message: &[u8]) -> [u8; 64]{
        self.input_length = (message.len() * 8) as u128;

        // following adds the input to the block which will
        // be used for hash computation. The padding will be
        // computed after no full block can be used for hash
        // computation, as it would be to short (not 512-bit)
        for m in message.iter() {
            self.block[self.block_length] = *m;
            self.block_length += 1;

            // If block length reaches 128, block for hash 
            // computation is big enougth (1024-bit). 
            if self.block_length == 128 {
                self.block_length = 0;
                self.compute_hash();
            }
        }

        // After every 1024-Bit Block N is computed, padding
        // is added and computed to the hash value. In case
        // of needing an extra block, as padding would be 
        // too long, computing addtional block as well.
        let additional_block: bool = self.add_padding();
        self.compute_hash();

        if additional_block == true {
            self.block = self.additional_padding_block;
            self.compute_hash();
        }

        self.parse_u64_array_to_u8_array(&self.output)
    }

    pub fn string(&self) -> String {
        let hash_value: [u8; 64] = self.parse_u64_array_to_u8_array(&self.output);
        hash_value.iter().map(|x| format!("{:02x}", x)).collect::<String>()
    }

    fn add_padding(&mut self) -> bool {

        let mut additional_block_length: usize = 0;

        // adding one '1' bit, and seven '0' bits
        self.block[self.block_length] = 0x80;
        self.block_length += 1;

        // adding K '0' bits where L is length of input
        // and K solves: ( L + 1 + K ) mod 1024 = 896
        let mut k: u128 = 1;
        loop {
            if ((self.input_length + 1) + k) % 1024 == 896 {
                break;
            } else {
                k += 1;
            }
        }

        // as seven '0' bits were previously added and 
        // for K applies following: K - 7 = 8 * x; 
        // K-7 '0' bits are missing and will be added:
        let mut k_rounds: u128 = (k - 7) / 8;
        while k_rounds > 0 {
            if self.block_length <= 127 {
                self.block[self.block_length] = 0x00;
                self.block_length += 1;
            } else if additional_block_length <= 127{
                self.additional_padding_block[additional_block_length] = 0x00;
                additional_block_length += 1;
            }
            k_rounds -= 1;
        }

        // transforms the length of the input into a 
        // 64-bit representation and adds it to padding 
        let input_length_bit_repr: [u8; 16] = self.input_length.to_be_bytes();

        for i in input_length_bit_repr.iter() {
            if self.block_length <= 127 {
                self.block[self.block_length] = *i;
                self.block_length += 1;
            } else if additional_block_length <= 127 {
                self.additional_padding_block[additional_block_length] = *i;
                additional_block_length += 1;
            }
        }

        // If addtional padding block was used, return true, else false.
        if additional_block_length == 0 {
            false
        } else {
            true
        }
    }

    fn compute_hash(&mut self) -> () {
        let k: [u64; 80] = [
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, 
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70, 
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b, 
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        ];

        let mut w: [u64; 80] = [0; 80];
        
        let m: [u64; 16] = self.parse_u8_array_to_u64_array(&self.block);

        // Initialize the working variables
        let mut a: u64 = self.output[0];
        let mut b: u64 = self.output[1];
        let mut c: u64 = self.output[2];
        let mut d: u64 = self.output[3];
        let mut e: u64 = self.output[4];
        let mut f: u64 = self.output[5];
        let mut g: u64 = self.output[6];
        let mut h: u64 = self.output[7];

        for t in 0..80 {
            if t < 16 {
                w[t] = m[t];
            } else if t < 80 {
                w[t] = add(
                        add(ssig1(w[t-2]), w[t-7]), 
                        add(ssig0(w[t-15]), w[t-16])
                        );
            }

            let t1: u64 = add(
                            h, 
                            add(
                                add(
                                    bsig1(e), 
                                    ch(e,f,g)
                                    ), 
                                add(
                                    k[t], 
                                    w[t]
                                    )
                                )
                            );
            let t2: u64 = add(
                            bsig0(a), 
                            maj(a,b,c)
                            );
            h = g;
            g = f;
            f = e;
            e = add(d, t1);
            d = c;
            c = b;
            b = a;
            a = add(t1, t2);
        }
        
        self.output[0] = add(a, self.output[0]);
        self.output[1] = add(b, self.output[1]);
        self.output[2] = add(c, self.output[2]);
        self.output[3] = add(d, self.output[3]);
        self.output[4] = add(e, self.output[4]);
        self.output[5] = add(f, self.output[5]);
        self.output[6] = add(g, self.output[6]);
        self.output[7] = add(h, self.output[7]);
    }
    
    fn parse_u8_array_to_u64_array(&self, input: &[u8; 128]) -> [u64; 16] {
        // Transforms a [u8; 64] array to an [u32; 16] array.
        let mut output: [u64; 16] = [0; 16];

        for (i, chunk) in input.chunks_exact(8).enumerate() {
            output[i] = u64::from_be_bytes(chunk.try_into().unwrap());
        }
        output
    }

    fn parse_u64_array_to_u8_array(&self, input: &[u64; 8]) -> [u8; 64] {
        // Transforms a [u64; 8] array to an [u8; 64] array.
        let mut output = [0u8; 64];

        for i in 0..8 {
            for j in 0..8 {
                output[(i * 8) + j] = ((input[i].rotate_right((64 - (j+1) * 8) as u32)) & 0xFF) as u8;
            }
        }

        output
    }
}


#[cfg(test)]
mod tests {
    use super::Sha512;

    #[test]
    fn test_parse_functions() {
        let u64_array: [u64; 8] = [
            0x1122334455667788, 0x99AABBCCDDEEFF00, 0x0011223344556677, 0x8899AABBCCDDEEFF,
            0x1020304050607080, 0x90A0B0C0D0E0F000, 0xF0E0D0C0B0A09080, 0x7060504030201000
        ];

        let u8_array: [u8; 128] = [
            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
            0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99,
            0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
            0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
            0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10,
            0x00, 0xF0, 0xE0, 0xD0, 0xC0, 0xB0, 0xA0, 0x90,
            0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
            0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
            0x89, 0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB,
            0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA, 0x98,
            0x75, 0xB9, 0xFD, 0xAC, 0xDF, 0x9B, 0x57, 0x13,
            0x24, 0xDF, 0xB9, 0xE3, 0xCE, 0x68, 0x24, 0x02,
            0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10,
            0x00, 0xF0, 0xE0, 0xD0, 0xC0, 0xB0, 0xA0, 0x90,
            0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
            0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70
        ];

        let sha512: Sha512 = Sha512::new();

        let res_u64_array: [u8; 64] = sha512.parse_u64_array_to_u8_array(&u64_array);
        let res_u8_array: [u64; 16]  = sha512.parse_u8_array_to_u64_array(&u8_array);

        let expected_u64_array: [u8; 64] = [17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255, 0, 0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 0, 240, 224, 208, 192, 176, 160, 144, 128, 112, 96, 80, 64, 48, 32, 16, 0];
        let expected_u8_array: [u64; 16] = [9833440827789222417, 72038755451251353, 8603657889541918976, 18441921395520346504, 9255003132036915216, 67801181601177744, 9264081114510713072, 4538991236898928, 9900958322455989675, 8526495043095935640, 8483090292056741651, 2657046693243528194, 9255003132036915216, 67801181601177744, 9264081114510713072, 4538991236898928];
        
        assert_eq!(res_u64_array, expected_u64_array);
        assert_eq!(res_u8_array, expected_u8_array);
    }

    #[test]
    fn sha512_test() {
        // Test Vectors from https://eips.ethereum.org/assets/eip-2680/sha256-384-512.pdf
        let message1: &str = "abc";
        let expected_hash_1: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    
        let message2: &str = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let expected_hash_2: &str = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909";

        let mut sha512_1: Sha512 = Sha512::new();
        sha512_1.digest(&message1.as_bytes());

        let mut sha512_2: Sha512 = Sha512::new();
        sha512_2.digest(&message2.as_bytes());

        assert_eq!(sha512_1.string(), expected_hash_1);
        assert_eq!(sha512_2.string(), expected_hash_2);
    }

}