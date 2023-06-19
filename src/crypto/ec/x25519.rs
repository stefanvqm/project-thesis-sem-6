/* Author: Stefan Goetz, 2023
Warranty Disclaimer: the software is provided "as is" without any warranties or conditions.
Implementation according to https://martin.kleppmann.com/papers/curve25519.pdf
*/

#![allow(dead_code)]

pub type FieldElement = [i64; 16];

fn carry25519(input: &mut FieldElement) {
    for i in 0..16 {
        let carry: i64 = input[i] >> 16;
        input[i] -= carry << 16;
        if i < 15 {
            input[i + 1] += carry;
        } else {
            input[0] += 38 * carry;
        }
    }
}

pub fn unpack25519(input: &[u8; 32]) -> FieldElement {
    let mut output: FieldElement = [0; 16];

    for i in 0..16 {
        output[i] = ((input[2 * i + 1] as i64) << 8) +  (input[2 * i] as i64);
    }
    output[15] &= 0x7fff;
    output
}

pub fn pack25519(input: &mut FieldElement) -> [u8; 32] {
    let mut t: FieldElement = *input;
    let mut m: FieldElement = [0; 16];

    carry25519(&mut t);
    carry25519(&mut t);
    carry25519(&mut t);

    for _ in 0..2 {
        m[0] = t[0] - 0xFFED;
        for i in 1..15 {
            m[i] = t[i] - 0xFFFF - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xFFFF;
        }

        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let carry = (m[15] >> 16) & 1;
        m[14] &= 0xffff;

        swap25519(&mut t, &mut m, 1 - carry);
    }

    let mut output: [u8; 32] = [0; 32];
    for i in 0..16 {
        output[2 * i] = t[i] as u8;
        output[2 * i + 1] = (t[i] >> 8) as u8;
    }

    output
}

pub fn fadd(x: &FieldElement, y: &FieldElement) -> FieldElement {
    let mut output: FieldElement = [0; 16];

    for i in 0..16 {
        output[i] = x[i] + y[i]
    }

    output
}

pub fn fsub(x: &FieldElement, y: &FieldElement) -> FieldElement {
    let mut output: FieldElement = [0; 16];

    for i in 0..16 {
        output[i] = x[i] - y[i]
    }

    output
}

pub fn fmul(x: &FieldElement, y: &FieldElement) -> FieldElement {
    let mut output: FieldElement = [0; 16];
    let mut product: [i64; 31] = [0; 31]; 
    
    for i in 0..16 {
        for j in 0..16 {
            product[i+j] += x[i] * y[j];
        }
    }

    for i in 0..15 {
        /* Demonstrated in demonstration above */
        product[i] += 38 * product[i + 16]; 
    }
    
    for i in 0..16 {
        output[i] += product[i];
    }
    
    carry25519(&mut output);
    carry25519(&mut output);
    
    output
}

fn finverse(input: &FieldElement) -> FieldElement {
    let mut c: FieldElement = *input;

    for i in (0..=253).rev() {
        c = fmul(&c, &c);
        
        if i != 2 && i != 4 {
            c = fmul(&c, &input);
        }
    }

    c
}

fn swap25519(p: &mut FieldElement, q: &mut FieldElement, bit: i64) {
    let c: i64 = !(bit - 1);
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

pub fn scalarmult(point: &[u8; 32], scalar: &[u8; 32]) -> [u8; 32] {
    let mut clamped: [u8; 32] = *scalar;
    clamped[0] &= 0xf8;
    clamped[31] = (clamped[31] & 0x7f) | 0x40;

    let mut a:FieldElement = [0; 16];
    let mut b:FieldElement = [0; 16];
    let mut c:FieldElement = [0; 16];
    let mut d:FieldElement = [0; 16];
    let mut e:FieldElement;
    let mut f:FieldElement;

    let x: FieldElement = unpack25519(point);
    for i in 0..16 {
        b[i] = x[i];
        (d[i], a[i], c[i]) = (0, 0, 0);
    }
    (a[0], d[0]) = (1, 1);
    let mut constant: FieldElement = [0; 16];
    constant[0] = 121665;
    for i in (0..=254).rev() {
        let bit = ((clamped[i >> 3] >> (i & 7)) & 1) as i64;
        swap25519(&mut a, &mut b, bit);
        swap25519(&mut c, &mut d, bit);
        e = fadd(&a, &c);
        a = fsub(&a, &c);
        c = fadd(&b, &d);
        b = fsub(&b, &d);
        d = fmul(&e, &e);
        f = fmul(&a, &a);
        a = fmul(&c, &a);
        c = fmul(&b, &e);
        e = fadd(&a, &c);
        a = fsub(&a, &c);
        b = fmul(&a, &a);
        c = fsub(&d, &f);
        a = fmul(&c, &constant);
        a = fadd(&a, &d);
        c = fmul(&c, &a);
        a = fmul(&d, &f);
        d = fmul(&b, &x);
        b = fmul(&e, &e);
        swap25519(&mut a, &mut b, bit);
        swap25519(&mut c, &mut d, bit);
    }
    c = finverse(&c);
    a = fmul(&a, &c);
    pack25519(&mut a)
}

pub fn scalarmult_64bytes(point: &[u8; 32], scalar: &[u8; 64]) -> [u8; 32] {
    let mut clamped: [u8; 64] = *scalar;
    clamped[0] &= 0xf8;
    clamped[63] = (clamped[63] & 0x7f) | 0x40;

    let mut a: FieldElement = [0; 16];
    let mut b: FieldElement = [0; 16];
    let mut c: FieldElement = [0; 16];
    let mut d: FieldElement = [0; 16];
    let mut e: FieldElement;
    let mut f: FieldElement;

    let x: FieldElement = unpack25519(point);
    for i in 0..16 {
        b[i] = x[i];
        (d[i], a[i], c[i]) = (0, 0, 0);
    }
    (a[0], d[0]) = (1, 1);
    let mut constant: FieldElement = [0; 16];
    constant[0] = 121665;
    for i in (0..=254).rev() {
        let bit = ((clamped[i >> 3] >> (i & 7)) & 1) as i64;
        swap25519(&mut a, &mut b, bit);
        swap25519(&mut c, &mut d, bit);
        e = fadd(&a, &c);
        a = fsub(&a, &c);
        c = fadd(&b, &d);
        b = fsub(&b, &d);
        d = fmul(&e, &e);
        f = fmul(&a, &a);
        a = fmul(&c, &a);
        c = fmul(&b, &e);
        e = fadd(&a, &c);
        a = fsub(&a, &c);
        b = fmul(&a, &a);
        c = fsub(&d, &f);
        a = fmul(&c, &constant);
        a = fadd(&a, &d);
        c = fmul(&c, &a);
        a = fmul(&d, &f);
        d = fmul(&b, &x);
        b = fmul(&e, &e);
        swap25519(&mut a, &mut b, bit);
        swap25519(&mut c, &mut d, bit);
    }
    c = finverse(&c);
    a = fmul(&a, &c);
    pack25519(&mut a)
}

#[cfg(test)]
mod tests {
    use crate::crypto::ec::scalarmult;

    fn input_scalar_test(input_u_coordinate: [u8; 32], input_scalar: [u8; 32], output_u_coordinate: [u8; 32]) {
        assert_eq!(output_u_coordinate, scalarmult(&input_u_coordinate, &input_scalar));
    }
    
    #[test] 
    fn test_vectors_1() {
        // Test-Vectors from: https://datatracker.ietf.org/doc/html/rfc7748#section-5.2
        let input_scalar_1: [u8; 32] = [0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4];
        let input_u_coordinate_1: [u8; 32] = [0xe6 ,0xdb ,0x68 ,0x67 ,0x58 ,0x30 ,0x30 ,0xdb ,0x35 ,0x94 ,0xc1 ,0xa4 ,0x24 ,0xb1 ,0x5f ,0x7c ,0x72 ,0x66 ,0x24 ,0xec ,0x26 ,0xb3 ,0x35 ,0x3b ,0x10 ,0xa9 ,0x03 ,0xa6 ,0xd0 ,0xab ,0x1c ,0x4c];
        let output_u_coordinate_1: [u8; 32] = [0xc3 ,0xda ,0x55 ,0x37 ,0x9d ,0xe9 ,0xc6 ,0x90 ,0x8e ,0x94 ,0xea ,0x4d ,0xf2 ,0x8d ,0x08 ,0x4f ,0x32 ,0xec ,0xcf ,0x03 ,0x49 ,0x1c ,0x71 ,0xf7 ,0x54 ,0xb4 ,0x07 ,0x55 ,0x77 ,0xa2 ,0x85 ,0x52];

        input_scalar_test(input_u_coordinate_1, input_scalar_1, output_u_coordinate_1);
    }

    #[test] 
    fn test_vectors_2() {
        // Test-Vectors from: https://datatracker.ietf.org/doc/html/rfc7748#section-5.2
        let input_scalar_2: [u8; 32] = [0x4b, 0x66, 0xe9, 0xd4, 0xd1, 0xb4, 0x67, 0x3c, 0x5a, 0xd2, 0x26, 0x91, 0x95, 0x7d, 0x6a, 0xf5, 0xc1, 0x1b, 0x64, 0x21, 0xe0, 0xea, 0x01, 0xd4, 0x2c, 0xa4, 0x16, 0x9e, 0x79, 0x18, 0xba, 0x0d];
        let input_u_coordinate_2: [u8; 32] = [0xe5, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3, 0xf4, 0xb7, 0x95, 0x9d, 0x05, 0x38, 0xae, 0x2c, 0x31, 0xdb, 0xe7, 0x10, 0x6f, 0xc0, 0x3c, 0x3e, 0xfc, 0x4c, 0xd5, 0x49, 0xc7, 0x15, 0xa4, 0x93];
        let output_u_coordinate_2: [u8; 32] = [0x95, 0xcb, 0xde, 0x94, 0x76, 0xe8, 0x90, 0x7d, 0x7a, 0xad, 0xe4, 0x5c, 0xb4, 0xb8, 0x73, 0xf8, 0x8b, 0x59, 0x5a, 0x68, 0x79, 0x9f, 0xa1, 0x52, 0xe6, 0xf8, 0xf7, 0x64, 0x7a, 0xac, 0x79, 0x57];
        
        input_scalar_test(input_u_coordinate_2, input_scalar_2, output_u_coordinate_2);
    }


}
