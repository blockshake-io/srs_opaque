use blstrs::{Compress, G2Affine, Gt};
use generic_array::sequence::Concat;
use rand::Rng;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use typenum::Unsigned;
use zeroize::ZeroizeOnDrop;

use crate::{
    ciphersuite::{
        AuthCode, Bytes, Digest, LenAuthRequest, LenCredentialRequest, LenCredentialResponse,
        LenEnvelope, LenGt, LenKeyExchange1, LenMaskedResponse, LenNonce, Nonce,
    },
    error::InternalError,
    keypair::PublicKey,
    payload::Payload,
    serialization, Result,
};

#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct Envelope {
    pub nonce: Nonce,
    pub auth_tag: AuthCode,
}

impl Envelope {
    pub fn zero() -> Self {
        Self {
            nonce: Nonce::default(),
            auth_tag: AuthCode::default(),
        }
    }

    pub fn serialize(&self) -> Bytes<LenEnvelope> {
        self.nonce.concat(self.auth_tag)
    }

    pub fn deserialize(buf: &[u8]) -> Result<Envelope> {
        if buf.len() != LenEnvelope::to_usize() {
            return Err(InternalError::DeserializeError.into());
        }
        let nonce = Nonce::clone_from_slice(&buf[0..LenNonce::to_usize()]);
        let auth_tag = AuthCode::clone_from_slice(&buf[LenNonce::to_usize()..]);
        Ok(Envelope { nonce, auth_tag })
    }
}

#[derive(Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RegistrationRecord<P: Payload> {
    #[serde(with = "serialization::b64_envelope")]
    pub envelope: Envelope,
    #[serde(with = "serialization::b64_digest")]
    pub masking_key: Digest,
    #[zeroize(skip)]
    #[serde(with = "serialization::b64_public_key")]
    pub client_public_key: PublicKey,
    #[zeroize(skip)]
    pub payload: P,
}

impl<P: Payload> RegistrationRecord<P> {
    pub fn fake<R: CryptoRngCore>(rng: &mut R, payload: P) -> Self {
        let mut masking_key = Digest::default();
        masking_key.fill_with(|| rng.gen());
        Self {
            envelope: Envelope::zero(),
            masking_key,
            client_public_key: PublicKey::random(rng),
            payload,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct RegistrationRequest {
    #[zeroize(skip)]
    #[serde(with = "serialization::b64_g2")]
    pub blinded_element: G2Affine,
    pub client_identity: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationResponse {
    #[serde(with = "serialization::b64_gt")]
    pub evaluated_element: Gt,
    #[serde(with = "serialization::b64_public_key")]
    pub server_public_key: PublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialRequest {
    #[serde(with = "serialization::b64_g2")]
    pub blinded_element: G2Affine,
}

impl CredentialRequest {
    fn serialize(&self) -> Bytes<LenCredentialRequest> {
        let buf = self.blinded_element.to_compressed();
        Bytes::clone_from_slice(&buf)
    }
}

#[derive(Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct AuthRequest {
    #[serde(with = "serialization::b64_nonce")]
    pub client_nonce: Nonce,
    #[zeroize(skip)]
    #[serde(with = "serialization::b64_public_key")]
    pub client_public_keyshare: PublicKey,
}

impl AuthRequest {
    fn serialize(&self) -> Bytes<LenAuthRequest> {
        self.client_nonce
            .concat(self.client_public_keyshare.serialize())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyExchange1 {
    pub credential_request: CredentialRequest,
    pub auth_request: AuthRequest,
}

impl KeyExchange1 {
    pub fn serialize(&self) -> Bytes<LenKeyExchange1> {
        let credential_request = self.credential_request.serialize();
        let auth_request = self.auth_request.serialize();
        credential_request.concat(auth_request)
    }
}

#[derive(Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct CredentialResponse {
    #[zeroize(skip)]
    pub evaluated_element: Gt,
    #[serde(with = "serialization::b64_nonce")]
    pub masking_nonce: Nonce,
    #[serde(with = "serialization::b64_masked_response")]
    pub masked_response: Bytes<LenMaskedResponse>,
}

impl CredentialResponse {
    pub fn serialize(&self) -> Result<Bytes<LenCredentialResponse>> {
        let mut gt = Bytes::<LenGt>::default();
        self.evaluated_element
            .write_compressed(&mut gt[..])
            .map_err(|_| InternalError::SerializeError)?;
        Ok(gt.concat(self.masking_nonce).concat(self.masked_response))
    }
}

#[derive(Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct AuthResponse {
    #[serde(with = "serialization::b64_nonce")]
    pub server_nonce: Nonce,
    #[zeroize(skip)]
    #[serde(with = "serialization::b64_public_key")]
    pub server_public_keyshare: PublicKey,
    #[serde(with = "serialization::b64_auth_code")]
    pub server_mac: AuthCode,
}

#[derive(Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct KeyExchange2<P: Payload> {
    pub credential_response: CredentialResponse,
    pub auth_response: AuthResponse,
    #[zeroize(skip)]
    pub payload: P,
}

#[derive(Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct KeyExchange3 {
    #[serde(with = "serialization::b64_auth_code")]
    pub client_mac: AuthCode,
}
