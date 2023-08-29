use blstrs::{Compress, G2Affine, Gt};
use generic_array::sequence::Concat;
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
    Result,
};

#[derive(ZeroizeOnDrop)]
pub struct Envelope {
    pub nonce: Nonce,
    pub auth_tag: AuthCode,
}

impl Envelope {
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

#[derive(ZeroizeOnDrop)]
pub struct RegistrationRecord<P: Payload> {
    pub envelope: Envelope,
    pub masking_key: Digest,
    pub client_public_key: PublicKey,
    pub payload: P,
}

#[derive(ZeroizeOnDrop)]
pub struct RegistrationRequest {
    #[zeroize(skip)]
    pub blinded_element: G2Affine,
    pub client_identity: String,
}

#[derive(ZeroizeOnDrop)]
pub struct RegistrationResponse {
    #[zeroize(skip)]
    pub evaluated_element: Gt,
    pub server_public_key: PublicKey,
}

#[derive(ZeroizeOnDrop)]
pub struct CredentialRequest {
    #[zeroize(skip)]
    pub blinded_element: G2Affine,
}

impl CredentialRequest {
    fn serialize(&self) -> Bytes<LenCredentialRequest> {
        let buf = self.blinded_element.to_compressed();
        Bytes::clone_from_slice(&buf)
    }
}

#[derive(ZeroizeOnDrop)]
pub struct AuthRequest {
    pub client_nonce: Nonce,
    pub client_public_keyshare: PublicKey,
}

impl AuthRequest {
    fn serialize(&self) -> Bytes<LenAuthRequest> {
        self.client_nonce
            .concat(self.client_public_keyshare.serialize())
    }
}

#[derive(ZeroizeOnDrop)]
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

#[derive(ZeroizeOnDrop)]
pub struct CredentialResponse {
    #[zeroize(skip)]
    pub evaluated_element: Gt,
    pub masking_nonce: Nonce,
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

#[derive(ZeroizeOnDrop)]
pub struct AuthResponse {
    pub server_nonce: Nonce,
    pub server_public_keyshare: PublicKey,
    pub server_mac: AuthCode,
}

#[derive(ZeroizeOnDrop)]
pub struct KeyExchange2<P: Payload> {
    pub credential_response: CredentialResponse,
    pub auth_response: AuthResponse,
    pub payload: P,
}

#[derive(ZeroizeOnDrop)]
pub struct KeyExchange3 {
    pub client_mac: AuthCode,
}
