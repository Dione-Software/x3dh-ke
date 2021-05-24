//! [![Crate](https://img.shields.io/crates/v/x3dh-ke)](https://crates.io/crates/x3dh-ke)
//! [![License](https://img.shields.io/crates/l/x3dh-ke)](https://github.com/Decentrailzed-Communication-System/x3dh-ke/blob/67f5470a0e3199c79700410dfd207c93cf63d5be/LICENSE)
//! [![Actions](https://img.shields.io/github/workflow/status/Decentrailzed-Communication-System/x3dh-ke/Rust)](https://github.com/Decentrailzed-Communication-System/x3dh-ke/actions/workflows/rust.yml)
//!
//! # Implementation of X3DH
//! Implementation of extended triple diffie hellman written in Rust, as described by [Signal][1].
//! WARNING! This crate hasn't been reviewed and may include serious faults. Use with care.
//!
//! # Example Usage:
//!
//! ## Standard:
//! ```
//! use x3dh_ke::{IdentityKey, SignedPreKey, EphemeralKey, OneTimePreKey, Key, x3dh_a, x3dh_b};
//! let ika = IdentityKey::default();
//! let ikas = ika.strip();
//! let ikb = IdentityKey::default();
//! let ikbs = ikb.strip();
//! let spkb = SignedPreKey::default();
//! let spkbs = spkb.strip();
//! let eka = EphemeralKey::default();
//! let ekas = eka.strip();
//! let opkb = OneTimePreKey::default();
//! let opkbs = opkb.strip();
//! let signature = ikb.sign(&spkbs.pk_to_bytes());
//! let cka = x3dh_a(&signature, &ika, &spkbs, &eka, &ikbs, &opkbs).unwrap();
//! let ckb = x3dh_b(&ikas, &spkb, &ekas, &ikb, &opkb);
//! assert_eq!(cka, ckb)
//! ```
//!
//! ## Serialize and Deserialize
//! Every key described by this library can be turned into bytes and created from them too.
//! ```
//! use x3dh_ke::{IdentityKey, Key};
//! let ika = IdentityKey::default();
//! let data = ika.to_bytes();
//! let ikr = IdentityKey::from_bytes(&data).unwrap();
//! assert_eq!(ika.to_bytes(), ikr.to_bytes())
//! ```
//!
//! ## Strip Private Key
//! To share a key, the private part has to be striped previously from that.
//! ```
//! use x3dh_ke::{IdentityKey, Key};
//! let ika = IdentityKey::default();
//! let _iks = ika.strip(); // Without private key
//! ```
//!
//!
//! [1]: https://signal.org/docs/specifications/x3dh/

#![no_std]

extern crate alloc;

use p256::{SecretKey, PublicKey};
use p256::ecdh::SharedSecret;
use p256::elliptic_curve::ecdh::diffie_hellman;
use p256::{
    ecdsa::{SigningKey, Signature, signature::Signer}
};
use p256::ecdsa::{VerifyingKey, signature::Verifier};
use sha2::Sha512;

#[cfg(feature = "bytes")]
use serde::{Serialize, Deserialize};
use rand_core::{OsRng, RngCore};
use core::str::FromStr;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::string::ToString;

type Hkdf = hkdf::Hkdf<Sha512>;

#[cfg_attr(test, derive(Debug))]
pub struct IdentityKey(Option<SecretKey>, PublicKey);

impl Key for IdentityKey {
    fn default() -> Self {
        let private_key = SecretKey::random(&mut OsRng);
        let public_key = PublicKey::from_secret_scalar(private_key.secret_scalar());
        Self(Some(private_key), public_key)
    }

    fn ex_private_key(&self) -> Option<SecretKey> {
        self.0.clone()
    }

    fn ex_public_key(&self) -> PublicKey {
        self.1
    }

    fn strip(&self) -> Self {
        let public_key = self.ex_public_key();
        Self(None, public_key)
    }

    #[cfg(feature = "bytes")]
    fn to_bytes(&self) -> Vec<u8> {
        let ex_key = ExKey::from(self);
        bincode::serialize(&ex_key).unwrap()
    }

    #[cfg(feature = "bytes")]
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> where Self: Sized {
        let ex_key: ExKey = match bincode::deserialize(data) {
            Ok(d) => d,
            Err(_) => {
                return Err("error deserializing");
            }
        };
        match ex_key.kind {
            KeyType::Identity => {
                Ok(Self(ex_key.ex_private_key(), ex_key.ex_public_key()))
            }
            _ => {
                Err("Contains wrong key type")
            }
        }
    }
}

impl From<&IdentityKey> for ExKey {
    fn from(ik: &IdentityKey) -> Self {
        let private_key = ik.ex_private_key().map(|k| k.to_bytes().to_vec());
        let public_key = ik.ex_public_key().to_string().as_bytes().into();
        Self {
            kind: KeyType::Identity,
            private_key,
            public_key,
        }
    }
}

impl Drop for IdentityKey {
    fn drop(&mut self) {
        self.0 = Some(SecretKey::random(&mut OsRng));
        self.1 = PublicKey::from_secret_scalar(self.0.as_ref().unwrap().secret_scalar());
    }
}

pub struct EphemeralKey(Option<SecretKey>, PublicKey);

impl Key for EphemeralKey {
    fn default() -> Self {
        let private_key = SecretKey::random(&mut OsRng);
        let public_key = PublicKey::from_secret_scalar(private_key.secret_scalar());
        Self(Some(private_key), public_key)
    }

    fn ex_private_key(&self) -> Option<SecretKey> {
        self.0.clone()
    }

    fn ex_public_key(&self) -> PublicKey {
        self.1
    }

    fn strip(&self) -> Self {
        let public_key = self.ex_public_key();
        Self(None, public_key)
    }

    #[cfg(feature = "bytes")]
    fn to_bytes(&self) -> Vec<u8> {
        let ex_key = ExKey::from(self);
        bincode::serialize(&ex_key).unwrap()
    }

    #[cfg(feature = "bytes")]
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> where Self: Sized {
        let ex_key: ExKey = match bincode::deserialize(data) {
            Ok(d) => d,
            Err(_) => {
                return Err("Error deserializing")
            }
        };
        match ex_key.kind {
            KeyType::Ephemeral => {
                Ok(Self(ex_key.ex_private_key(), ex_key.ex_public_key()))
            }
            _ => {
                Err("Contains wrong key type")
            }
        }
    }
}

impl From<&EphemeralKey> for ExKey {
    fn from(ek: &EphemeralKey) -> Self {
        let private_key = ek.ex_private_key().map(|k| k.to_bytes().to_vec());
        let public_key = ek.ex_public_key().to_string().as_bytes().into();
        Self {
            kind: KeyType::Ephemeral,
            private_key,
            public_key,
        }
    }
}

impl Drop for EphemeralKey {
    fn drop(&mut self) {
        self.0 = Some(SecretKey::random(&mut OsRng));
        self.1 = PublicKey::from_secret_scalar(self.0.as_ref().unwrap().secret_scalar());
    }
}

pub struct SignedPreKey(Option<SecretKey>, PublicKey);

impl SignedPreKey {
    pub fn pk_to_bytes(&self) -> Vec<u8> {
        self.ex_public_key().to_string().as_bytes().to_vec()
    }
}

impl Key for SignedPreKey {
    fn default() -> Self {
        let private_key = SecretKey::random(&mut OsRng);
        let public_key = PublicKey::from_secret_scalar(private_key.secret_scalar());
        Self(Some(private_key), public_key)
    }

    fn ex_private_key(&self) -> Option<SecretKey> {
        self.0.clone()
    }

    fn ex_public_key(&self) -> PublicKey {
        self.1
    }

    fn strip(&self) -> Self {
        let public_key = self.ex_public_key();
        Self(None, public_key)
    }

    #[cfg(feature = "bytes")]
    fn to_bytes(&self) -> Vec<u8> {
        let ex_key = ExKey::from(self);
        bincode::serialize(&ex_key).unwrap()
    }

    #[cfg(feature = "bytes")]
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> where Self: Sized {
        let ex_key: ExKey = match bincode::deserialize(data) {
            Ok(d) => d,
            Err(_) => {
                return Err("Error deserializing")
            }
        };
        match ex_key.kind {
            KeyType::SignedPre => {
                Ok(Self(ex_key.ex_private_key(), ex_key.ex_public_key()))
            }
            _ => {
                Err("Contains wrong key type")
            }
        }
    }
}

impl From<&SignedPreKey> for ExKey {
    fn from(spk: &SignedPreKey) -> Self {
        let private_key = spk.ex_private_key().map(|k| k.to_bytes().to_vec());
        let public_key = spk.ex_public_key().to_string().as_bytes().into();
        Self {
            kind: KeyType::SignedPre,
            private_key,
            public_key
        }
    }
}

impl Drop for SignedPreKey {
    fn drop(&mut self) {
        self.0 = Some(SecretKey::random(&mut OsRng));
        self.1 = PublicKey::from_secret_scalar(self.0.as_ref().unwrap().secret_scalar());
    }
}

pub struct OneTimePreKey(Option<SecretKey>, PublicKey);

impl Key for OneTimePreKey {
    fn default() -> Self {
        let private_key = SecretKey::random(&mut OsRng);
        let public_key = PublicKey::from_secret_scalar(private_key.secret_scalar());
        Self(Some(private_key), public_key)
    }

    fn ex_private_key(&self) -> Option<SecretKey> {
        self.0.clone()
    }

    fn ex_public_key(&self) -> PublicKey {
        self.1
    }

    fn strip(&self) -> Self {
        let public_key = self.ex_public_key();
        Self(None, public_key)
    }

    #[cfg(feature = "bytes")]
    fn to_bytes(&self) -> Vec<u8> {
        let ex_key = ExKey::from(self);
        bincode::serialize(&ex_key).unwrap()
    }

    #[cfg(feature = "bytes")]
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> where Self: Sized {
        let ex_key: ExKey = match bincode::deserialize(data) {
            Ok(d) => d,
            Err(_) => {
                return Err("Error deserializing")
            }
        };
        match ex_key.kind {
            KeyType::OneTimePre => {
                Ok(Self(ex_key.ex_private_key(), ex_key.ex_public_key()))
            }
            _ => {
                Err("Contains wrong key type")
            }
        }
    }
}

impl From<&OneTimePreKey> for ExKey {
    fn from(otpk: &OneTimePreKey) -> Self {
        let private_key = otpk.ex_private_key().map(|k| k.to_bytes().to_vec());
        let public_key = otpk.ex_public_key().to_string().as_bytes().into();
        Self {
            kind: KeyType::OneTimePre,
            private_key,
            public_key,
        }
    }
}

impl Drop for OneTimePreKey {
    fn drop(&mut self) {
        self.0 = Some(SecretKey::random(&mut OsRng));
        self.1 = PublicKey::from_secret_scalar(self.0.as_ref().unwrap().secret_scalar());
    }
}

#[cfg_attr(feature = "bytes", derive(Serialize, Deserialize))]
enum KeyType {
    Identity,
    Ephemeral,
    SignedPre,
    OneTimePre,
}

#[cfg_attr(feature = "bytes", derive(Serialize, Deserialize))]
struct ExKey {
    kind: KeyType,
    #[cfg_attr(feature = "bytes", serde(with = "serde_bytes"))]
    private_key: Option<Vec<u8>>,
    #[cfg_attr(feature = "bytes", serde(with = "serde_bytes"))]
    public_key: Vec<u8>,
}

impl Drop for ExKey {
    fn drop(&mut self) {
        self.kind = KeyType::Ephemeral;
        let length = match &self.private_key {
            Some(d) => d.len(),
            None => 100,
        };
        let mut fill_data = Vec::with_capacity(length);
        OsRng::fill_bytes(&mut OsRng, &mut fill_data);
        self.private_key = Some(fill_data);
        OsRng::fill_bytes(&mut OsRng, &mut self.public_key);
    }
}

impl ExKey {
    pub(crate) fn ex_private_key(&self) -> Option<SecretKey> {
        self.private_key.clone().map(|k| SecretKey::from_bytes(&k).unwrap())
    }

    pub(crate) fn ex_public_key(&self) -> PublicKey {
        let public_key_str = String::from_utf8(self.public_key.clone()).unwrap();
        PublicKey::from_str(&public_key_str).unwrap()
    }
}

pub trait Key {
    fn default() -> Self;
    fn ex_private_key(&self) -> Option<SecretKey>;
    fn ex_public_key(&self) -> PublicKey;
    fn diffie_hellman<T: Key>(&self, other: &T) -> SharedSecret {
        let sk = self.ex_private_key().unwrap();
        let pk = other.ex_public_key();
        diffie_hellman(
            sk.secret_scalar(),
            pk.as_affine(),
        )
    }
    fn sign(&self, data: &[u8]) -> Signature {
        let signing_key = SigningKey::from(self.ex_private_key().unwrap());
        signing_key.sign(data)
    }
    fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let verify_key = VerifyingKey::from(self.ex_public_key());
        verify_key.verify(message, signature).is_ok()
    }
    fn strip(&self) -> Self;

    #[cfg(feature = "bytes")]
    fn to_bytes(&self) -> Vec<u8>;
    #[cfg(feature = "bytes")]
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> where Self: Sized;
}

pub fn x3dh_a(signature: &Signature, ika: &IdentityKey, spkb: &SignedPreKey,
              eka: &EphemeralKey, ikb: &IdentityKey, opkb: &OneTimePreKey) -> Result<[u8; 32], &'static str> {
    let result = ikb.verify(&spkb.pk_to_bytes(), signature);
    if !result {
        return Err("Signature couldn't be verified")
    }
    let mut dh1 = ika.diffie_hellman(spkb).as_bytes().to_vec();
    let mut dh2 = eka.diffie_hellman(ikb).as_bytes().to_vec();
    let mut dh3 = eka.diffie_hellman(spkb).as_bytes().to_vec();
    let mut dh4 = eka.diffie_hellman(opkb).as_bytes().to_vec();
    let mut data = Vec::new();
    let mut null_data = [0_u8; 32].to_vec();
    data.append(&mut null_data);
    data.append(&mut dh1);
    data.append(&mut dh2);
    data.append(&mut dh3);
    data.append(&mut dh4);
    let h = Hkdf::new(Some(&[0_u8; 32]), &data);
    let mut okm = [0_u8; 32];
    let info = b"X3DH";
    h.expand(info, &mut okm).unwrap();
    Ok(okm)
}

pub fn x3dh_b(ika: &IdentityKey, spkb: &SignedPreKey,
              eka: &EphemeralKey, ikb: &IdentityKey, opkb: &OneTimePreKey) -> [u8; 32] {
    let mut dh1 = spkb.diffie_hellman(ika).as_bytes().to_vec();
    let mut dh2 = ikb.diffie_hellman(eka).as_bytes().to_vec();
    let mut dh3 = spkb.diffie_hellman(eka).as_bytes().to_vec();
    let mut dh4 = opkb.diffie_hellman(eka).as_bytes().to_vec();
    let mut data = Vec::new();
    let mut null_data = [0_u8; 32].to_vec();
    data.append(&mut null_data);
    data.append(&mut dh1);
    data.append(&mut dh2);
    data.append(&mut dh3);
    data.append(&mut dh4);
    let h = Hkdf::new(Some(&[0_u8; 32]), &data);
    let mut okm = [0_u8; 32];
    let info = b"X3DH";
    h.expand(info, &mut okm).unwrap();
    okm
}

pub fn calc_ad(ika: &IdentityKey, ikb: &IdentityKey) -> Vec<u8> {
    let mut res = Vec::new();
    let ika_pk = ika.ex_public_key();
    let ikb_pk = ikb.ex_public_key();
    let mut ika_pk_data = ika_pk.to_string().as_bytes().to_vec();
    let mut ikb_pk_data = ikb_pk.to_string().as_bytes().to_vec();
    res.append(&mut ika_pk_data);
    res.append(&mut ikb_pk_data);
    res
}

#[cfg(test)]
mod x3dh_test {
    use crate::{IdentityKey, Key, SignedPreKey, EphemeralKey, OneTimePreKey, x3dh_a, x3dh_b};

    #[test]
    fn x3dh_test() {
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
    }
}

#[cfg(test)]
mod identity_key_test {
    use crate::{IdentityKey, Key};

    #[test]
    fn identity_key_dh() {
        let ika = IdentityKey::default();
        let ikb = IdentityKey::default();
        let shared_secret_1 = ika.diffie_hellman(&ikb);
        let shared_secret_2 = ikb.diffie_hellman(&ika);
        assert_eq!(shared_secret_1.as_bytes(), shared_secret_2.as_bytes())
    }

    #[test]
    fn identity_key_sign() {
        let ika = IdentityKey::default();
        let data = b"Hello World".to_vec();
        let signature = ika.sign(&data);
        assert!(ika.verify(&data, &signature))
    }

    #[test]
    fn identity_key_strip() {
        let ika = IdentityKey::default();
        let iks = ika.strip();
        let secret_1 = ika.diffie_hellman(&iks);
        let secret_2 = ika.diffie_hellman(&ika);
        assert_eq!(secret_1.as_bytes(), secret_2.as_bytes())
    }

    #[test]
    #[should_panic]
    fn identity_key_strip_fail() {
        let ika = IdentityKey::default();
        let iks = ika.strip();
        let _secret = iks.diffie_hellman(&iks);
    }

    #[test]
    #[cfg(feature = "bytes")]
    fn identity_key_bytes_full() {
        let ika = IdentityKey::default();
        let bytes = ika.to_bytes();
        let ikr = IdentityKey::from_bytes(&bytes).unwrap();
        let secret_1 = ika.diffie_hellman(&ika);
        let secret_2 = ikr.diffie_hellman(&ikr);
        assert_eq!(secret_1.as_bytes(), secret_2.as_bytes())
    }

    #[test]
    #[cfg(feature = "bytes")]
    fn identity_key_bytes_strip() {
        let ika = IdentityKey::default();
        let iks = ika.strip();
        let data = iks.to_bytes();
        let ikr = IdentityKey::from_bytes(&data).unwrap();
        assert_eq!(iks.to_bytes(), ikr.to_bytes())
    }
}

#[cfg(test)]
mod ephemeral_key_test {
    use crate::{EphemeralKey, Key};

    #[test]
    fn ephemeral_key_dh() {
        let epka = EphemeralKey::default();
        let epkb = EphemeralKey::default();
        let shared_secret_1 = epka.diffie_hellman(&epkb);
        let shared_secret_2 = epkb.diffie_hellman(&epka);
        assert_eq!(shared_secret_1.as_bytes(), shared_secret_2.as_bytes())
    }

    #[test]
    fn ephemeral_key_sign() {
        let epka = EphemeralKey::default();
        let data = b"Hello World".to_vec();
        let signature = epka.sign(&data);
        assert!(epka.verify(&data, &signature))
    }

    #[test]
    fn ephemeral_key_strip() {
        let epka = EphemeralKey::default();
        let epks = epka.strip();
        let secret_1 = epka.diffie_hellman(&epks);
        let secret_2 = epka.diffie_hellman(&epka);
        assert_eq!(secret_1.as_bytes(), secret_2.as_bytes())
    }

    #[test]
    #[should_panic]
    fn ephemeral_key_strip_fail() {
        let epka = EphemeralKey::default();
        let epks = epka.strip();
        let secret_1 = epka.diffie_hellman(&epka);
        let secret_2 = epks.diffie_hellman(&epks);
        assert_eq!(secret_1.as_bytes(), secret_2.as_bytes())
    }

    #[test]
    #[cfg(feature = "bytes")]
    fn ephemeral_key_bytes_full() {
        let epka = EphemeralKey::default();
        let bytes = epka.to_bytes();
        let epkr = EphemeralKey::from_bytes(&bytes).unwrap();
        let secret_1 = epka.diffie_hellman(&epka);
        let secret_2 = epkr.diffie_hellman(&epkr);
        assert_eq!(secret_1.as_bytes(), secret_2.as_bytes())
    }

    #[test]
    #[cfg(feature = "bytes")]
    fn ephemeral_key_bytes_strip() {
        let epka = EphemeralKey::default();
        let epks = epka.strip();
        let data = epks.to_bytes();
        let epkr = EphemeralKey::from_bytes(&data).unwrap();
        assert_eq!(epks.to_bytes(), epkr.to_bytes())
    }
}

#[cfg(test)]
mod signed_pre_key_test {
    use crate::{SignedPreKey, Key};

    #[test]
    fn signed_pre_key_dh() {
        let spka = SignedPreKey::default();
        let spkb = SignedPreKey::default();
        let shared_secret_1 = spka.diffie_hellman(&spkb);
        let shared_secret_2 = spkb.diffie_hellman(&spka);
        assert_eq!(shared_secret_1.as_bytes(), shared_secret_2.as_bytes())
    }

    #[test]
    fn signed_pre_key_sign() {
        let spka = SignedPreKey::default();
        let data = b"Hello World".to_vec();
        let signature = spka.sign(&data);
        assert!(spka.verify(&data, &signature))
    }

    #[test]
    fn signed_pre_key_strip() {
        let spka = SignedPreKey::default();
        let spks = spka.strip();
        let secret_1 = spka.diffie_hellman(&spks);
        let secret_2 = spka.diffie_hellman(&spka);
        assert_eq!(secret_1.as_bytes(), secret_2.as_bytes())
    }

    #[test]
    #[should_panic]
    fn signed_pre_key_strip_fail() {
        let spka = SignedPreKey::default();
        let spks = spka.strip();
        let _secret = spks.diffie_hellman(&spks);
    }

    #[test]
    #[cfg(feature = "bytes")]
    fn signed_pre_key_bytes_full() {
        let spka = SignedPreKey::default();
        let bytes = spka.to_bytes();
        let spkr = SignedPreKey::from_bytes(&bytes).unwrap();
        let secret_1 = spka.diffie_hellman(&spka);
        let secret_2 = spkr.diffie_hellman(&spkr);
        assert_eq!(secret_1.as_bytes(), secret_2.as_bytes())
    }

    #[test]
    #[cfg(feature = "bytes")]
    fn signed_pre_key_bytes_strip() {
        let spka = SignedPreKey::default();
        let spks = spka.strip();
        let data = spks.to_bytes();
        let spkr = SignedPreKey::from_bytes(&data).unwrap();
        assert_eq!(spks.to_bytes(), spkr.to_bytes())
    }
}

#[cfg(test)]
mod one_time_pre_key_test {
    use crate::{OneTimePreKey, Key};

    #[test]
    fn one_time_pre_key_dh() {
        let otpka = OneTimePreKey::default();
        let otpkb = OneTimePreKey::default();
        let shared_secret_1 = otpka.diffie_hellman(&otpkb);
        let shared_secret_2 = otpkb.diffie_hellman(&otpka);
        assert_eq!(shared_secret_1.as_bytes(), shared_secret_2.as_bytes())
    }

    #[test]
    fn one_time_pre_key_sign() {
        let otpka = OneTimePreKey::default();
        let data = b"Hello World".to_vec();
        let signature = otpka.sign(&data);
        assert!(otpka.verify(&data, &signature))
    }

    #[test]
    fn one_time_pre_key_strip() {
        let otpka = OneTimePreKey::default();
        let otpks = otpka.strip();
        let secret_1 = otpka.diffie_hellman(&otpks);
        let secret_2 = otpka.diffie_hellman(&otpka);
        assert_eq!(secret_1.as_bytes(), secret_2.as_bytes())
    }

    #[test]
    #[should_panic]
    fn one_time_pre_key_fail() {
        let otpka = OneTimePreKey::default();
        let otpks = otpka.strip();
        let _secret = otpks.diffie_hellman(&otpks);
    }

    #[test]
    #[cfg(feature = "bytes")]
    fn one_time_pre_key_bytes_full() {
        let otpka = OneTimePreKey::default();
        let bytes = otpka.to_bytes();
        let otpkr = OneTimePreKey::from_bytes(&bytes).unwrap();
        let secret_1 = otpka.diffie_hellman(&otpka);
        let secret_2 = otpkr.diffie_hellman(&otpkr);
        assert_eq!(secret_1.as_bytes(), secret_2.as_bytes())
    }

    #[test]
    #[cfg(feature = "bytes")]
    fn one_time_pre_key_bytes_strip() {
        let otpka = OneTimePreKey::default();
        let otpks = otpka.strip();
        let data = otpks.to_bytes();
        let otpkr = OneTimePreKey::from_bytes(&data).unwrap();
        assert_eq!(otpks.to_bytes(), otpkr.to_bytes())
    }
}
