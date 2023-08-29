use blstrs::{Compress, G2Affine, Gt};
use typenum::Sum;
use zeroize::ZeroizeOnDrop;

use crate::{
    ciphersuite::{
        AuthCode, Bytes, Digest, LenCredentialResponse, LenGt, LenKePublicKey, LenMaskedResponse,
        LenNonce, Nonce,
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
    fn serialize(&self) -> [u8; 96] {
        self.blinded_element.to_compressed()
    }
}

#[derive(ZeroizeOnDrop)]
pub struct AuthRequest {
    pub client_nonce: Nonce,
    pub client_public_keyshare: PublicKey,
}

pub type AuthRequestLen = Sum<LenNonce, LenKePublicKey>;
impl AuthRequest {
    fn serialize(&self) -> Bytes<AuthRequestLen> {
        let mut buf = Bytes::<AuthRequestLen>::default();
        buf[0..32].copy_from_slice(&self.client_nonce[..]);
        let public_key = self.client_public_keyshare.0.compress().to_bytes();
        buf[32..64].copy_from_slice(&public_key[..]);
        buf
    }
}

#[derive(ZeroizeOnDrop)]
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
        use generic_array::sequence::Concat;
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
