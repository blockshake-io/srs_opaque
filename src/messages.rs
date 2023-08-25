use std::io::Write;

use blstrs::{Compress, G2Affine, Gt};

use crate::{
    ciphersuite::{AuthCode, Digest, Nonce, LEN_MASKED_RESPONSE, LEN_NONCE, PublicKeyBytes},
    error::InternalError,
    keypair::PublicKey,
    Result,
};

pub struct CleartextCredentials {
    pub server_public_key: PublicKeyBytes,
    pub server_identity: Vec<u8>,
    pub client_identity: Vec<u8>,
}

impl CleartextCredentials {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::with_capacity(
            self.server_public_key.len() + self.server_identity.len() + self.client_identity.len(),
        );
        buf.extend(self.server_public_key);
        buf.extend(&self.server_identity[..]);
        buf.extend(&self.client_identity[..]);
        buf
    }
}

pub struct Envelope {
    pub nonce: Nonce,
    pub auth_tag: AuthCode,
}

impl Envelope {
    pub fn serialize(&self) -> [u8; 96] {
        let mut buf = [0; 96];
        buf[0..32].copy_from_slice(&self.nonce);
        buf[32..96].copy_from_slice(&self.auth_tag);
        buf
    }

    pub fn deserialize(buf: &[u8]) -> Result<Envelope> {
        if buf.len() != 96 {
            return Err(InternalError::DeserializeError.into());
        }
        let mut nonce = Nonce::default();
        let mut auth_tag = AuthCode::default();
        nonce.copy_from_slice(&buf[0..32]);
        auth_tag.copy_from_slice(&buf[32..96]);
        Ok(Envelope { nonce, auth_tag })
    }
}

pub struct RegistrationRecord {
    pub envelope: Envelope,
    pub masking_key: Digest,
    pub client_public_key: PublicKey,
}

pub struct RegistrationRequest {
    pub blinded_element: G2Affine,
    pub username: String,
}

pub struct RegistrationResponse {
    pub evaluated_element: Gt,
}

pub struct CredentialRequest {
    pub blinded_element: G2Affine,
}

impl CredentialRequest {
    fn serialize(&self) -> [u8; 96] {
        self.blinded_element.to_compressed()
    }
}

pub struct AuthRequest {
    pub client_nonce: [u8; LEN_NONCE],
    pub client_public_keyshare: PublicKey,
}

impl AuthRequest {
    fn serialize(&self) -> [u8; 64] {
        let mut buf = [0; LEN_NONCE + 32];
        buf[0..32].copy_from_slice(&self.client_nonce[..]);
        let public_key = self.client_public_keyshare.0.compress().to_bytes();
        buf[32..64].copy_from_slice(&public_key[..]);
        buf
    }
}

pub struct KeyExchange1 {
    pub credential_request: CredentialRequest,
    pub auth_request: AuthRequest,
}

impl KeyExchange1 {
    pub fn serialize(&self) -> [u8; 160] {
        let mut buf = [0; 160];
        let part1 = self.credential_request.serialize();
        let part2 = self.auth_request.serialize();
        buf[0..96].copy_from_slice(&part1[..]);
        buf[96..160].copy_from_slice(&part2[..]);
        buf
    }
}

pub struct CredentialResponse {
    pub evaluated_element: Gt,
    pub masking_nonce: Nonce,
    pub masked_response: [u8; LEN_MASKED_RESPONSE],
}

impl CredentialResponse {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(288 + LEN_NONCE + LEN_MASKED_RESPONSE);
        let err = |_| InternalError::SerializeError;
        self.evaluated_element
            .write_compressed(&mut buf)
            .map_err(err)?;
        buf.write_all(&self.masking_nonce[..]).map_err(err)?;
        buf.write_all(&self.masked_response).map_err(err)?;
        Ok(buf)
    }
}

pub struct AuthResponse {
    pub server_nonce: Nonce,
    pub server_public_keyshare: PublicKey,
    pub server_mac: AuthCode,
}

pub struct KeyExchange2 {
    pub credential_response: CredentialResponse,
    pub auth_response: AuthResponse,
}

pub struct KeyExchange3 {
    pub client_mac: AuthCode,
}
