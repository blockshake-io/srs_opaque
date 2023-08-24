use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar, RistrettoPoint};

use crate::error::InternalError;

pub struct PublicKey(pub RistrettoPoint);

impl PublicKey {
    pub fn serialize(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    pub fn deserialize(buf: &[u8]) -> Result<PublicKey, InternalError> {
        let foo = CompressedRistretto::from_slice(&buf[..])
            .map_err(|_| InternalError::DeserializeError)?;
        match foo.decompress() {
            Some(pk) => Ok(PublicKey(pk)),
            None => Err(InternalError::DeserializeError),
        }
    }
}

pub struct SecretKey(pub Scalar);

impl SecretKey {
    pub fn serialize(&self) -> [u8; 32] {
        self.0.as_bytes().clone()
    }
}

pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}
