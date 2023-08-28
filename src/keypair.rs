use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar, RistrettoPoint};

use crate::{
    ciphersuite::{PublicKeyBytes, SecretKeyBytes},
    error::{Error, InternalError},
};

#[derive(Clone)]
pub struct PublicKey(pub RistrettoPoint);

impl PublicKey {
    pub fn serialize(&self) -> PublicKeyBytes {
        self.0.compress().to_bytes().into()
    }

    pub fn deserialize(buf: &[u8]) -> Result<PublicKey, Error> {
        let foo = CompressedRistretto::from_slice(&buf[..])
            .map_err(|_| InternalError::DeserializeError)?;
        match foo.decompress() {
            Some(pk) => Ok(PublicKey(pk)),
            None => Err(InternalError::DeserializeError.into()),
        }
    }
}

pub struct SecretKey(pub Scalar);

impl SecretKey {
    pub fn serialize(&self) -> SecretKeyBytes {
        self.0.to_bytes().into()
    }
}

pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}
