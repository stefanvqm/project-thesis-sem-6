
### About

This project is intendet to:
- learn Rust
- learn how to read and implement Standards 
- deep diving into some crypto standards 
  
In the end, a small and **not** useful blockchain can be build without using any foreign dependencies. The only crate that is currently in usage is: ```rand = "0.8.4"```.

#### Working on
- [Ed25519 - Implementation Guide](https://www.eiken.dev/blog/2020/11/code-spotlight-the-reference-implementation-of-ed25519-part-1/) 
  - [Ed25519 - RFC](https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.2)
  - [Ed25519 - Parameter](https://neuromancer.sk/std/other/Ed25519)

#### Currently implemented (including standards)
- [Sha256](https://datatracker.ietf.org/doc/html/rfc6234)
- [Sha512](https://datatracker.ietf.org/doc/html/rfc6234)
- [HMAC-256 & HMAC-512](https://www.rfc-editor.org/rfc/rfc2104)
- [X25519](https://martin.kleppmann.com/papers/curve25519.pdf)
- [AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
- [AES_CBC](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)

#### Test Vectors
- [Sha256](https://helix.stormhub.org/papers/SHA-256.pdf)
- [Sha512](https://eips.ethereum.org/assets/eip-2680/sha256-384-512.pdf)
- [HMAC-256](https://www.rfc-editor.org/rfc/rfc2104)
- [X25519](https://datatracker.ietf.org/doc/html/rfc7748#section-5.2)
- [AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
- [CBC](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)


#### Other Data
- [Curve25519: parameters](https://neuromancer.sk/std/other/Curve25519)
- [Curve25519: How to use](https://cr.yp.to/ecdh.html#use)

#### Helpful Tools
- https://www.mobilefish.com/services/big_number/big_number.php 