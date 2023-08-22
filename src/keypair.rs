use curve25519_dalek::{scalar::Scalar, RistrettoPoint};

pub struct PublicKey(pub RistrettoPoint);

impl PublicKey {
    pub fn serialize(&self) -> [u8; 32] {
        self.0.compress().as_bytes().clone()
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
