//! A module for implementing hash functions supporting `monotree`.
use std::convert::TryInto;

use crate::utils::*;
use crate::*;
use digest::Digest;
use ff::{PrimeFieldRepr, PrimeField};
use poseidon_rs::{Poseidon as PoseidonHash, Fr, FrRepr};

/// A trait defining hashers used for `monotree`
pub trait Hasher {
    fn new() -> Self;
    fn digest(&self, bytes: &[u8]) -> Hash;
}

fn bytes_into_frs(bytes: &[u8]) -> Vec<Fr> {
    let chunk_size = 31;
    bytes
        .chunks(chunk_size.try_into().expect("Couldn't convert int"))
        .map(|c| {
            let mut buf = [0; 32];
            buf[..c.len()].copy_from_slice(c);
            let mut fr = FrRepr::from(0);
            fr.read_le(&buf[..])
                .expect("Could not read the chunk");
            let f = Fr::from_repr(fr)
                .expect("Could not convert the input bytes to a field element");
            println!("Feild: {:?}", f);
            f
        })
        .collect()
}

#[derive(Clone, Debug)]
pub struct Poseidon;
impl Hasher for Poseidon {
    fn new() -> Self {
        Poseidon
    }

    fn digest(&self, bytes: &[u8]) -> Hash {
        let frs = bytes_into_frs(bytes);
        let p = PoseidonHash::new();
        let hash = p.hash(frs)
            .expect("Could not hash this value with poseidon.");
        let hash_repr = hash.into_repr();
        let mut hash_bytes: [u8; 32] = [0; 32];
        hash_repr.write_le(&mut hash_bytes[..])
            .expect("Could not write the hash result to 32 bytes le buffer");
        println!("HASH: {:?}", hash_bytes);
        hash_bytes
    }
}

#[derive(Clone, Debug)]
/// A hasher using `Blake2s` hash function
pub struct Blake2s;
impl Hasher for Blake2s {
    fn new() -> Self {
        Blake2s
    }

    fn digest(&self, bytes: &[u8]) -> Hash {
        let mut hasher = blake2_rfc::blake2s::Blake2s::new(HASH_LEN);
        hasher.update(bytes);
        let hash = hasher.finalize();
        slice_to_hash(hash.as_bytes())
    }
}

#[derive(Clone, Debug)]
/// A hasher using `Blake2b` hash function
pub struct Blake2b;
impl Hasher for Blake2b {
    fn new() -> Self {
        Blake2b
    }

    fn digest(&self, bytes: &[u8]) -> Hash {
        let mut hasher = blake2_rfc::blake2b::Blake2b::new(HASH_LEN);
        hasher.update(bytes);
        let hash = hasher.finalize();
        slice_to_hash(hash.as_bytes())
    }
}

#[derive(Clone, Debug)]
/// A hasher using `Blake3` hash function
pub struct Blake3;
impl Hasher for Blake3 {
    fn new() -> Self {
        Blake3
    }

    /// Currently supports 256-bit or 32-byte only.
    fn digest(&self, bytes: &[u8]) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(bytes);
        let hash = hasher.finalize();
        slice_to_hash(hash.as_bytes())
    }
}

#[derive(Clone, Debug)]
/// A hasher using `SHA2` hash function
pub struct Sha2;
impl Hasher for Sha2 {
    fn new() -> Self {
        Sha2
    }

    /// Currently supports 256-bit or 32-byte only.
    fn digest(&self, bytes: &[u8]) -> Hash {
        let mut hasher = sha2::Sha256::new();
        hasher.input(bytes);
        let hash = hasher.result();
        slice_to_hash(hash.as_slice())
    }
}

#[derive(Clone, Debug)]
/// A hasher using `SHA3` or `Keccak` hash function
pub struct Sha3;
impl Hasher for Sha3 {
    fn new() -> Self {
        Sha3
    }

    /// Currently supports 256-bit or 32-byte only.
    fn digest(&self, bytes: &[u8]) -> Hash {
        let mut hasher = sha3::Sha3_256::new();
        hasher.input(bytes);
        let hash = hasher.result();
        slice_to_hash(hash.as_slice())
    }
}
