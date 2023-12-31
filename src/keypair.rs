use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar, RistrettoPoint};
use rand_core::CryptoRngCore;
use zeroize::ZeroizeOnDrop;

use crate::{
    ciphersuite::{PublicKeyBytes, SecretKeyBytes},
    error::InternalError,
    Result,
};

#[derive(Debug, Copy, Clone)]
pub struct PublicKey(pub RistrettoPoint);

impl PublicKey {
    pub fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self(RistrettoPoint::random(rng))
    }

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

    pub fn deserialize(buf: &[u8]) -> Result<SecretKey> {
        let buf: &[u8; 32] = buf.try_into()
            .map_err(|_| InternalError::DeserializeError)?;
        let res = Scalar::from_canonical_bytes(*buf);
        if res.is_some().into() {
            Ok(SecretKey(res.unwrap()))
        } else {
            Err(InternalError::DeserializeError.into())
        }
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

    pub fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self::from_secret_key(Scalar::random(rng))
    }
}
