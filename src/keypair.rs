use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar, RistrettoPoint};
use zeroize::ZeroizeOnDrop;

use crate::{
    ciphersuite::{PublicKeyBytes, SecretKeyBytes},
    error::InternalError,
    Result,
};

#[derive(Debug, Copy, Clone)]
pub struct PublicKey(pub RistrettoPoint);

impl PublicKey {
    pub fn serialize(&self) -> PublicKeyBytes {
        self.0.compress().to_bytes().into()
    }

    pub fn deserialize(buf: &[u8]) -> Result<PublicKey> {
        let res = CompressedRistretto::from_slice(&buf[..])
            .map_err(|_| InternalError::DeserializeError)?;
        match res.decompress() {
            Some(pk) => Ok(PublicKey(pk)),
            None => Err(InternalError::DeserializeError.into()),
        }
    }
}

#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct SecretKey(pub Scalar);

impl SecretKey {
    pub fn serialize(&self) -> SecretKeyBytes {
        self.0.to_bytes().into()
    }
}

#[derive(ZeroizeOnDrop)]
pub struct KeyPair {
    #[zeroize(skip)]
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl KeyPair {
    pub fn from_secret_key(sk: Scalar) -> Self {
        Self {
            secret_key: SecretKey(sk),
            public_key: PublicKey(RistrettoPoint::mul_base(&sk)),
        }
    }
}
