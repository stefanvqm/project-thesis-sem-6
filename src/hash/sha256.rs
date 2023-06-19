/* Author: Stefan Goetz, 2023
Warranty Disclaimer: the software is provided "as is" without any warranties or conditions.
Implementation according to https://datatracker.ietf.org/doc/html/rfc6234
*/

fn rotr(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}

fn shr(x: u32, n: u32) -> u32 {
    x >> n
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((!x) & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn bsig0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

fn bsig1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

fn ssig0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)
}

fn ssig1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)
}

fn add(x: u32, y: u32) -> u32 {
    x.wrapping_add(y)
}

pub struct Sha256 {
    block: [u8; 64],
    block_length: usize,
    additional_padding_block: [u8; 64],
    output: [u32; 8],
    input_length: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            block: [0; 64],
            block_length: 0,
            additional_padding_block: [0; 64],
            output: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
            ],
            input_length: 0,
        }
    }

    pub fn digest(&mut self, message: &[u8]) -> [u8; 32]{
        self.input_length = (message.len() * 8) as u64;

        // following adds the input to the block which will
        // be used for hash computation. The padding will be
        // computed after no full block can be used for hash
        // computation, as it would be to short (not 512-bit)
        for m in message.iter() {
            self.block[self.block_length] = *m;
            self.block_length += 1;

            // If block length reaches 64, block for hash 
            // computation is big enougth (512-bit). 
            if self.block_length == 64 {
                self.block_length = 0;
                self.compute_hash();
            }
        }

        // After every 512-Bit Block N is computed, padding
        // is added and computed to the hash value. In case
        // of needing an extra block, as padding would be 
        // too long, computing addtional block as well.
        let additional_block: bool = self.add_padding();
        self.compute_hash();

        if additional_block == true {
            self.block = self.additional_padding_block;
            self.compute_hash();
        }

        self.parse_u32_array_to_u8_array(&self.output)
    }

    pub fn string(&self) -> String {
        let hash_value = self.parse_u32_array_to_u8_array(&self.output);
        hash_value.iter().map(|x: &u8| format!("{:02x}", x)).collect::<String>()
    }

    fn add_padding(&mut self) -> bool {

        let mut additional_block_length: usize = 0;

        // adding one '1' bit, and seven '0' bits
        self.block[self.block_length] = 0x80;
        self.block_length += 1;

        // adding K '0' bits where L is length of input
        // and K solves: ( L + 1 + K ) mod 512 = 448
        let mut k: u64 = 1;
        loop {
            if ((self.input_length + 1) + k) % 512 == 448 {
                break;
            } else {
                k += 1;
            }
        }

        // as seven '0' bits were previously added and 
        // for K applies following: K - 7 = 8 * x; 
        // K-7 '0' bits are missing and will be added:
        let mut k_rounds: u64 = (k - 7) / 8;
        while k_rounds > 0 {
            if self.block_length <= 63 {
                self.block[self.block_length] = 0x00;
                self.block_length += 1;
            } else if additional_block_length <= 63{
                self.additional_padding_block[additional_block_length] = 0x00;
                additional_block_length += 1;
            }
            k_rounds -= 1;
        }

        // transforms the length of the input into a 
        // 64-bit representation and adds it to padding 
        let input_length_bit_repr: [u8; 8] = self.input_length.to_be_bytes();

        for i in input_length_bit_repr.iter() {
            if self.block_length <= 63 {
                self.block[self.block_length] = *i;
                self.block_length += 1;
            } else if additional_block_length <= 63 {
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
        let k: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ];

        let mut w: [u32; 64] = [0; 64];
        
        let m: [u32; 16] = self.parse_u8_array_to_u32_array(&self.block);

        // Initialize the working variables
        let mut a: u32 = self.output[0];
        let mut b: u32 = self.output[1];
        let mut c: u32 = self.output[2];
        let mut d: u32 = self.output[3];
        let mut e: u32 = self.output[4];
        let mut f: u32 = self.output[5];
        let mut g: u32 = self.output[6];
        let mut h: u32 = self.output[7];

        for t in 0..64 {
            if t < 16 {
                w[t] = m[t];
            } else if t < 64 {
                w[t] = add(
                        add(ssig1(w[t-2]), w[t-7]), 
                        add(ssig0(w[t-15]), w[t-16])
                        );
            }

            let t1: u32 = add(
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
            let t2: u32 = add(
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
    
    fn parse_u8_array_to_u32_array(&self, input: &[u8; 64]) -> [u32; 16] {
        // Transforms a [u8; 64] array to an [u32; 16] array.
        let mut output: [u32; 16] = [0; 16];

        for i in 0..16 {
            output[i] = u32::from_be_bytes([
                input[i * 4],
                input[i * 4 + 1],
                input[i * 4 + 2],
                input[i * 4 + 3],
            ]);
        }
        output
    }

    fn parse_u32_array_to_u8_array(&self, input: &[u32; 8]) -> [u8; 32] {
        // Transforms a [u32; 8] array to an [u8; 32] array.
        let mut output = [0u8; 32];
        for i in 0..8 {
            let num = input[i];
            output[i * 4 + 3] = (num & 0xFF) as u8;
            output[i * 4 + 2] = ((num >> 8) & 0xFF) as u8;
            output[i * 4 + 1] = ((num >> 16) & 0xFF) as u8;
            output[i * 4] = ((num >> 24) & 0xFF) as u8;
        }
        output
    }
}


#[cfg(test)]
mod tests {
    use crate::Sha256;
    
    #[test]
    fn sha_256_test() {
    // Following test values will use test inputs from 
    // https://helix.stormhub.org/papers/SHA-256.pdf
        fn check_sha_256(message: &[u8], correct_value: &str) {
            let mut sha: Sha256 = Sha256::new();
            sha.digest(message);

            assert_eq!(sha.string(), correct_value);
        }

        let message1 :&[u8] = "abc".as_bytes();
        let message2 :&[u8] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();
        let message3 :String = ["a"; 1_000_000].concat();

        check_sha_256(&message1, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        check_sha_256(&message2, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        check_sha_256(&message3.as_bytes(), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }
}