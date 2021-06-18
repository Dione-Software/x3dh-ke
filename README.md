[![Crate](https://img.shields.io/crates/v/x3dh-ke)](https://crates.io/crates/x3dh-ke)
[![License](https://img.shields.io/github/license/Dione-Software/x3dh-ke)](https://github.com/Dione-Software/x3dh-ke/blob/master/LICENSE)
[![Coverage Status](https://coveralls.io/repos/github/Dione-Software/x3dh-ke/badge.svg?branch=main)](https://coveralls.io/github/Dione-Software/x3dh-ke?branch=master)
[![Workflow Status](https://github.com/Dione-Software/x3dh-ke/actions/workflows/rust.yml/badge.svg)](https://github.com/Dione-Software/x3dh-ke/actions/workflows/rust.yml)
![Maintenance](https://img.shields.io/badge/maintenance-activly--developed-brightgreen.svg)

# x3dh-ke

## Implementation of X3DH
Implementation of extended triple diffie hellman written in Rust, as described by [Signal][1].
WARNING! This crate hasn't been reviewed and may include serious faults. Use with care.

## Example Usage:

### Standard:
```rust
use x3dh_ke::{IdentityKey, SignedPreKey, EphemeralKey, OneTimePreKey, Key, x3dh_a, x3dh_b};
let ika = IdentityKey::default();
let ikas = ika.strip();
let ikb = IdentityKey::default();
let ikbs = ikb.strip();
let spkb = SignedPreKey::default();
let spkbs = spkb.strip();
let eka = EphemeralKey::default();
let ekas = eka.strip();
let opkb = OneTimePreKey::default();
let opkbs = opkb.strip();
let signature = ikb.sign(&spkbs.pk_to_bytes());
let cka = x3dh_a(&signature, &ika, &spkbs, &eka, &ikbs, &opkbs).unwrap();
let ckb = x3dh_b(&ikas, &spkb, &ekas, &ikb, &opkb);
assert_eq!(cka, ckb)
```

### Serialize and Deserialize
Every key described by this library can be turned into bytes and created from them too.
```rust
use x3dh_ke::{IdentityKey, Key};
let ika = IdentityKey::default();
let data = ika.to_bytes();
let ikr = IdentityKey::from_bytes(&data).unwrap();
assert_eq!(ika.to_bytes(), ikr.to_bytes())
```

### Strip Private Key
To share a key, the private part has to be striped previously from that.
```rust
use x3dh_ke::{IdentityKey, Key};
let ika = IdentityKey::default();
let _iks = ika.strip(); // Without private key
```


[1]: https://signal.org/docs/specifications/x3dh/

Current version: 0.1.2

License: MIT 
