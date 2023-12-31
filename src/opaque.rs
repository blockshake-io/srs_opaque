use blstrs::{Gt, Scalar};
use elliptic_curve::subtle::ConstantTimeEq;
use hkdf::HkdfExtract;
use rand::{CryptoRng, RngCore};
use typenum::Unsigned;
use zeroize::ZeroizeOnDrop;

pub type Stretch = dyn Fn(&[u8]) -> Result<Digest>;

use crate::{
    ciphersuite::*,
    error::{InternalError, ProtocolError},
    keypair::{KeyPair, PublicKey, SecretKey},
    messages::{
        AuthRequest, AuthResponse, CredentialRequest, CredentialResponse, Envelope, KeyExchange1,
        KeyExchange2, KeyExchange3, RegistrationRecord, RegistrationRequest, RegistrationResponse,
    },
    oprf, primitives, Result,
};

/// Options for specifying custom identifiers
#[derive(Clone, Copy, Debug, Default)]
pub struct Identifiers<'a> {
    /// Client identifier
    pub client: Option<&'a [u8]>,
    /// Server identifier
    pub server: Option<&'a [u8]>,
}

pub struct ClientRegistrationFlow<'a, Rng: CryptoRng + RngCore> {
    client_identity: &'a str,
    password: &'a [u8],
    server_public_key: &'a PublicKey,
    payload: &'a [u8],
    server_identity: Option<&'a str>,
    blinding_key: Option<Scalar>,
    rng: Rng,
}

impl<'a, Rng> ClientRegistrationFlow<'a, Rng>
where
    Rng: CryptoRng + RngCore,
{
    pub fn new(
        client_identity: &'a str,
        password: &'a [u8],
        server_public_key: &'a PublicKey,
        payload: &'a [u8],
        server_identity: Option<&'a str>,
        rng: Rng,
    ) -> ClientRegistrationFlow<'a, Rng> {
        ClientRegistrationFlow {
            client_identity,
            password,
            server_public_key,
            payload,
            server_identity,
            blinding_key: None,
            rng,
        }
    }

    pub fn start(&mut self) -> RegistrationRequest {
        let result = oprf::blind(self.password, &mut self.rng);
        self.blinding_key = Some(result.blinding_key);
        RegistrationRequest {
            client_identity: self.client_identity.to_string(),
            blinded_element: result.blinded_element,
        }
    }

    /// Corresponds to FinalizeRegistrationRequest
    pub fn finish<Stretch>(
        &self,
        response: &RegistrationResponse,
        stretch: Stretch,
    ) -> Result<(RegistrationRecord, Digest)>
    where
        Stretch: Fn(&[u8]) -> Result<Digest>,
    {
        let blinding_key = self.blinding_key.as_ref().expect("uninitialized");
        let oprf_output = oprf::finalize(self.password, &response.evaluated_element, blinding_key)?;
        let stretched_oprf_output = stretch(&oprf_output[..])?;
        let randomized_pwd =
            primitives::extract_kdf(&[&oprf_output[..], &stretched_oprf_output[..]])?;

        let mut client_rng = rand::thread_rng();
        Self::store(
            &mut client_rng,
            &randomized_pwd,
            self.server_public_key,
            self.server_identity,
            Some(&self.client_identity[..]),
            self.payload,
        )
    }

    /// Corresponds to Store
    fn store<R: CryptoRng + RngCore>(
        rng: &mut R,
        randomized_pwd: &Kdf,
        server_public_key: &PublicKey,
        server_identity: Option<&str>,
        client_identity: Option<&str>,
        payload: &'a [u8],
    ) -> Result<(RegistrationRecord, Digest)> {
        let mut nonce = Nonce::default();
        rng.fill_bytes(&mut nonce);

        let masking_key: Digest = primitives::expand(randomized_pwd, &[STR_MASKING_KEY])?;
        let auth_key: Digest = primitives::expand(randomized_pwd, &[&nonce, STR_AUTH_KEY])?;
        let export_key: Digest = primitives::expand(randomized_pwd, &[&nonce, STR_EXPORT_KEY])?;
        let seed: Seed = primitives::expand(randomized_pwd, &[&nonce, STR_PRIVATE_KEY])?;

        let client_keypair = primitives::derive_keypair(&seed, STR_DERIVE_DIFFIE_HELLMAN)?;

        let identifiers = Identifiers {
            client: client_identity.map(|x| x.as_bytes()),
            server: server_identity.map(|x| x.as_bytes()),
        };
        let cleartext_credentials = create_cleartext_credentials(
            &identifiers,
            server_public_key,
            &client_keypair.public_key,
        );
        let auth_tag = construct_auth_tag(&auth_key, &cleartext_credentials, &nonce, &payload)?;

        let registration_record = RegistrationRecord {
            envelope: Envelope { nonce, auth_tag },
            masking_key,
            client_public_key: client_keypair.public_key.clone(),
            payload: payload.to_vec(),
        };

        Ok((registration_record, export_key))
    }
}

pub struct ServerRegistrationFlow<'a> {
    server_public_key: &'a PublicKey,
}

impl<'a> ServerRegistrationFlow<'a> {
    pub fn new(server_public_key: &'a PublicKey) -> ServerRegistrationFlow<'a> {
        ServerRegistrationFlow { server_public_key }
    }

    /// Corresponds to CreateRegistrationResponse
    pub fn start(&self, evaluated_element: Gt) -> RegistrationResponse {
        RegistrationResponse {
            evaluated_element,
            server_public_key: self.server_public_key.clone(),
        }
    }

    pub fn finish(&self, _record: &RegistrationRecord) {
        // we need to decide what to do here
    }
}

pub struct ClientLoginFlow<'a, Rng>
where
    Rng: CryptoRng + RngCore,
{
    client_identity: &'a str,
    password: &'a [u8],
    blinding_key: Option<Scalar>,
    client_secret: Option<SecretKey>,
    ke1_serialized: Option<Bytes<LenKeyExchange1>>,
    rng: Rng,
}

impl<'a, Rng> ClientLoginFlow<'a, Rng>
where
    Rng: CryptoRng + RngCore,
{
    pub fn new(client_identity: &'a str, password: &'a [u8], rng: Rng) -> ClientLoginFlow<'a, Rng> {
        ClientLoginFlow {
            client_identity,
            password,
            blinding_key: None,
            client_secret: None,
            ke1_serialized: None,
            rng,
        }
    }

    /// Corresponds to GenerateKE1
    pub fn start(&mut self) -> Result<KeyExchange1> {
        // corresponds to CreateCredentialRequest
        let blind_result = oprf::blind(self.password, &mut self.rng);
        self.blinding_key = Some(blind_result.blinding_key);
        let credential_request = CredentialRequest {
            blinded_element: blind_result.blinded_element,
        };

        // corresponds to AuthClientStart
        let mut client_nonce = Nonce::default();
        self.rng.fill_bytes(&mut client_nonce);
        let mut client_keyshare_seed = Seed::default();
        self.rng.fill_bytes(&mut client_keyshare_seed);
        let client_keypair =
            primitives::derive_keypair(&client_keyshare_seed, STR_DERIVE_DIFFIE_HELLMAN)?;
        let auth_request = AuthRequest {
            client_nonce,
            client_public_keyshare: client_keypair.public_key.clone(),
        };
        let ke1 = KeyExchange1 {
            credential_request,
            auth_request,
        };

        self.client_secret = Some(client_keypair.secret_key.clone());
        self.ke1_serialized = Some(ke1.serialize());

        Ok(ke1)
    }

    /// Corresponds to GenerateKE3
    pub fn finish<S>(
        &self,
        server_identity: Option<&str>,
        ke2: &KeyExchange2,
        stretch: S,
    ) -> Result<(KeyExchange3, AuthCode, Digest)>
    where
        S: Fn(&[u8]) -> Result<Digest>,
    {
        let blinding_key = &self.blinding_key.expect("uninitialized");

        let (client_private_key, cleartext_credentials, _, export_key) = Self::recover_credentials(
            self.password,
            blinding_key,
            &ke2.credential_response,
            server_identity,
            self.client_identity,
            &ke2.payload,
            stretch,
        )?;

        let (ke3, session_key) =
            self.auth_client_finalize(&cleartext_credentials, &client_private_key, &ke2)?;

        Ok((ke3, session_key, export_key))
    }

    fn recover_credentials<S>(
        password: &[u8],
        blinding_key: &Scalar,
        response: &CredentialResponse,
        server_identity: Option<&str>,
        client_identity: &str,
        payload: &[u8],
        stretch: S,
    ) -> Result<(SecretKey, CleartextCredentials, PublicKey, Digest)>
    where
        S: Fn(&[u8]) -> Result<Digest>,
    {
        let oprf_output = oprf::finalize(password, &response.evaluated_element, blinding_key)?;
        let stretched_oprf_output = stretch(&oprf_output[..])?;
        let randomized_pwd =
            primitives::extract_kdf(&[&oprf_output[..], &stretched_oprf_output[..]])?;

        let masking_key: Digest = primitives::expand(&randomized_pwd, &[STR_MASKING_KEY])?;
        let mut xor_pad: Bytes<LenMaskedResponse> =
            primitives::create_xor_pad(&masking_key, &response.masking_nonce)?;

        for (x1, x2) in xor_pad.iter_mut().zip(&response.masked_response) {
            *x1 ^= x2;
        }

        let len_pk = LenKePublicKey::to_usize();
        let server_public_key = PublicKey::deserialize(&xor_pad[0..len_pk])
            .map_err(|_| ProtocolError::EnvelopeRecoveryError)?;
        let envelope = Envelope::deserialize(&xor_pad[len_pk..])?;

        let (client_private_key, cleartext_credentials, export_key) = Self::recover(
            &randomized_pwd,
            &server_public_key,
            &envelope,
            server_identity,
            Some(client_identity),
            payload,
        )?;

        Ok((
            client_private_key,
            cleartext_credentials,
            server_public_key,
            export_key,
        ))
    }

    fn recover(
        randomized_pwd: &Kdf,
        server_public_key: &PublicKey,
        envelope: &Envelope,
        server_identity: Option<&str>,
        client_identity: Option<&str>,
        payload: &[u8],
    ) -> Result<(SecretKey, CleartextCredentials, Digest)> {
        let auth_key: Digest =
            primitives::expand(randomized_pwd, &[&envelope.nonce, STR_AUTH_KEY])?;
        let export_key: Digest =
            primitives::expand(randomized_pwd, &[&envelope.nonce, STR_EXPORT_KEY])?;
        let seed: Seed = primitives::expand(randomized_pwd, &[&envelope.nonce, STR_PRIVATE_KEY])?;
        let client_keypair = primitives::derive_keypair(&seed, STR_DERIVE_DIFFIE_HELLMAN)?;

        let identifiers = Identifiers {
            client: client_identity.map(|x| x.as_bytes()),
            server: server_identity.map(|x| x.as_bytes()),
        };
        let cleartext_credentials = create_cleartext_credentials(
            &identifiers,
            &server_public_key,
            &client_keypair.public_key,
        );
        let expected_tag =
            construct_auth_tag(&auth_key, &cleartext_credentials, &envelope.nonce, payload)?;

        if bool::from(expected_tag.ct_eq(&envelope.auth_tag)) {
            Ok((
                client_keypair.secret_key.clone(),
                cleartext_credentials,
                export_key,
            ))
        } else {
            Err(ProtocolError::EnvelopeRecoveryError.into())
        }
    }

    fn auth_client_finalize(
        &self,
        cleartext_credentials: &CleartextCredentials,
        client_private_key: &SecretKey,
        ke2: &KeyExchange2,
    ) -> Result<(KeyExchange3, AuthCode)> {
        let client_secret = self.client_secret.as_ref().expect("uninitialized");
        let ke1_serialized = self.ke1_serialized.as_ref().expect("uninitialized");

        let server_public_key = PublicKey::deserialize(&cleartext_credentials.server_public_key)?;
        let dh1 =
            primitives::diffie_hellman(client_secret, &ke2.auth_response.server_public_keyshare);
        let dh2 = primitives::diffie_hellman(client_secret, &server_public_key);
        let dh3 = primitives::diffie_hellman(
            client_private_key,
            &ke2.auth_response.server_public_keyshare,
        );
        let ikm = &[&dh1[..], &dh2[..], &dh3[..]];

        let preamble_hasher = primitives::preamble_hasher(
            &cleartext_credentials.client_identity[..],
            ke1_serialized,
            &cleartext_credentials.server_identity[..],
            &ke2.credential_response.serialize()?[..],
            &ke2.auth_response.server_nonce,
            &ke2.auth_response.server_public_keyshare,
            &[],
        )?;
        let hashed_preamble = preamble_hasher.clone().finalize();

        let (km2, km3, session_key) = derive_keys(ikm, &hashed_preamble[..])?;
        let expected_server_mac = primitives::mac(&km2[..], &hashed_preamble[..])?;

        if !bool::from(expected_server_mac.ct_eq(&ke2.auth_response.server_mac)) {
            return Err(ProtocolError::ServerAuthenticationError.into());
        }

        use digest::Update;
        let client_mac = primitives::mac(
            &km3[..],
            &preamble_hasher.chain(&expected_server_mac).finalize(),
        )?;

        Ok((KeyExchange3 { client_mac }, session_key))
    }
}

pub struct ServerLoginState {
    pub session_key: AuthCode,
    pub expected_client_mac: AuthCode,
}

impl ServerLoginState {
    pub fn finish(&self, ke3: &KeyExchange3) -> Result<AuthCode> {
        if bool::from(ke3.client_mac.ct_eq(&self.expected_client_mac)) {
            Ok(self.session_key)
        } else {
            Err(ProtocolError::ServerAuthenticationError.into())
        }
    }
}

pub struct ServerLoginFlow<'a, Rng>
where
    Rng: CryptoRng + RngCore,
{
    server_public_key: &'a PublicKey,
    server_identity: Option<&'a str>,
    ke_keypair: &'a KeyPair,
    record: &'a RegistrationRecord,
    ke1: &'a KeyExchange1,
    client_identity: &'a str,
    rng: Rng,
}

impl<'a, Rng> ServerLoginFlow<'a, Rng>
where
    Rng: CryptoRng + RngCore,
{
    pub fn new(
        server_public_key: &'a PublicKey,
        server_identity: Option<&'a str>,
        ke_keypair: &'a KeyPair,
        record: &'a RegistrationRecord,
        ke1: &'a KeyExchange1,
        client_identity: &'a str,
        rng: Rng,
    ) -> Self {
        Self {
            server_public_key,
            server_identity,
            ke_keypair,
            record,
            ke1,
            client_identity,
            rng,
        }
    }

    /// Corresponds to GenerateKE2
    pub fn start(&mut self, evaluated_element: Gt) -> Result<(ServerLoginState, KeyExchange2)> {
        let credential_response = Self::create_credential_response(
            &mut self.rng,
            self.server_public_key,
            self.record,
            evaluated_element,
        )?;

        let ids = Identifiers {
            client: Some(self.client_identity.as_bytes()),
            server: self.server_identity.map(|x| x.as_bytes()),
        };
        let cleartext_credentials = create_cleartext_credentials(
            &ids,
            self.server_public_key,
            &self.record.client_public_key,
        );

        let (auth_response, session_key, expected_client_mac) = Self::auth_server_respond(
            &mut self.rng,
            &cleartext_credentials,
            &self.ke_keypair.secret_key,
            &self.record.client_public_key,
            &self.ke1,
            &credential_response,
        )?;

        let state = ServerLoginState {
            session_key,
            expected_client_mac,
        };
        let ke2 = KeyExchange2 {
            credential_response,
            auth_response,
            payload: self.record.payload.clone(),
        };

        Ok((state, ke2))
    }

    /// Corresponds to ServerFinish
    pub fn finish(&self, state: &ServerLoginState, ke3: &KeyExchange3) -> Result<AuthCode> {
        state.finish(ke3)
    }

    fn create_credential_response<R: CryptoRng + RngCore>(
        rng: &mut R,
        server_public_key: &PublicKey,
        record: &RegistrationRecord,
        evaluated_element: Gt,
    ) -> Result<CredentialResponse> {
        let mut masking_nonce = Nonce::default();
        rng.fill_bytes(&mut masking_nonce);

        let mut xor_pad: Bytes<LenMaskedResponse> =
            primitives::create_xor_pad(&record.masking_key, &masking_nonce)?;

        let server_public_key = server_public_key.serialize();
        let envelope = record.envelope.serialize();
        let credential_response = server_public_key.iter().chain(&envelope);
        for (x1, x2) in xor_pad.iter_mut().zip(credential_response) {
            *x1 ^= x2;
        }

        Ok(CredentialResponse {
            evaluated_element,
            masking_nonce,
            masked_response: xor_pad,
        })
    }

    fn auth_server_respond<R: CryptoRng + RngCore>(
        rng: &mut R,
        cleartext_credentials: &CleartextCredentials,
        server_secret_key: &SecretKey,
        client_public_key: &PublicKey,
        ke1: &KeyExchange1,
        credential_response: &CredentialResponse,
    ) -> Result<(AuthResponse, AuthCode, AuthCode)> {
        let mut server_nonce = Nonce::default();
        rng.fill_bytes(&mut server_nonce);
        let mut server_keyshare_seed = Seed::default();
        rng.fill_bytes(&mut server_keyshare_seed);
        let server_keypair =
            primitives::derive_keypair(&server_keyshare_seed, STR_DERIVE_DIFFIE_HELLMAN)?;

        let preamble_hasher = primitives::preamble_hasher(
            &cleartext_credentials.client_identity[..],
            &ke1.serialize()[..],
            &cleartext_credentials.server_identity[..],
            &credential_response.serialize()?[..],
            &server_nonce[..],
            &server_keypair.public_key,
            &[],
        )?;
        let hashed_preamble = preamble_hasher.clone().finalize();

        let dh1 = primitives::diffie_hellman(
            &server_keypair.secret_key,
            &ke1.auth_request.client_public_keyshare,
        );
        let dh2 = primitives::diffie_hellman(
            &server_secret_key,
            &ke1.auth_request.client_public_keyshare,
        );
        let dh3 = primitives::diffie_hellman(&server_keypair.secret_key, client_public_key);
        let ikm = &[&dh1[..], &dh2[..], &dh3[..]];

        let (km2, km3, session_key) = derive_keys(ikm, &hashed_preamble[..])?;
        let server_mac = primitives::mac(&km2[..], &hashed_preamble[..])?;
        use digest::Update;
        let expected_client_mac =
            primitives::mac(&km3[..], &preamble_hasher.chain(&server_mac).finalize())?;

        let auth_response = AuthResponse {
            server_nonce,
            server_mac,
            server_public_keyshare: server_keypair.public_key.clone(),
        };

        Ok((auth_response, session_key, expected_client_mac))
    }
}

fn derive_keys(ikm: &[&[u8]], hashed_preamble: &[u8]) -> Result<(AuthCode, AuthCode, AuthCode)> {
    let mut hkdf = HkdfExtract::<Hash>::new(None);
    for input in ikm {
        hkdf.input_ikm(input);
    }
    let (_, hkdf1) = hkdf.finalize();

    let handshake_secret = derive_secret(&hkdf1, STR_HANDSHAKE_SECRET, hashed_preamble)?;
    let session_key = derive_secret(&hkdf1, STR_SESSION_KEY, hashed_preamble)?;

    let hkdf = Kdf::from_prk(&handshake_secret[..]).map_err(|_| InternalError::HkdfError)?;
    let km2 = derive_secret(&hkdf, STR_SERVER_MAC, b"")?;
    let km3 = derive_secret(&hkdf, STR_CLIENT_MAC, b"")?;

    Ok((km2, km3, session_key))
}

fn derive_secret(hkdf: &Kdf, label: &[u8], transcript_hash: &[u8]) -> Result<Digest> {
    const STR_OPAQUE: &[u8] = b"OPAQUE-";
    let len_label = primitives::i2osp_2(STR_OPAQUE.len() + label.len())?;
    let len_extract = primitives::i2osp_2(LenPrk::to_usize())?;
    let len_context = primitives::i2osp_2(transcript_hash.len())?;

    let mut okm = Digest::default();
    hkdf.expand_multi_info(
        &[
            &len_extract[..],
            &len_label[..],
            STR_OPAQUE,
            label,
            &len_context[..],
            transcript_hash,
        ],
        &mut okm[..],
    )
    .map_err(|_| InternalError::HkdfError)?;

    Ok(okm)
}

fn create_cleartext_credentials(
    ids: &Identifiers,
    server_public_key: &PublicKey,
    client_public_key: &PublicKey,
) -> CleartextCredentials {
    let client_public_key = client_public_key.serialize();
    let server_public_key = server_public_key.serialize();
    let client_id = ids.client.unwrap_or(&client_public_key[..]);
    let server_id = ids.server.unwrap_or(&server_public_key[..]);
    CleartextCredentials {
        server_public_key,
        server_identity: Vec::from(server_id),
        client_identity: Vec::from(client_id),
    }
}

fn construct_auth_tag(
    auth_key: &[u8],
    cleartext_credentials: &CleartextCredentials,
    nonce: &[u8],
    payload: &[u8],
) -> Result<AuthCode> {
    let mut hmac = Mac::new_from_slice(&auth_key).map_err(|_| InternalError::HmacError)?;
    hmac.update(nonce);
    hmac.update(&cleartext_credentials.server_public_key);
    hmac.update(&cleartext_credentials.server_identity);
    hmac.update(&cleartext_credentials.client_identity);
    hmac.update(payload);
    Ok(hmac.finalize().into_bytes())
}

////////////////////////
//// Helper Structs ////
////////////////////////

#[derive(ZeroizeOnDrop)]
struct CleartextCredentials {
    server_public_key: PublicKeyBytes,
    server_identity: Vec<u8>,
    client_identity: Vec<u8>,
}
