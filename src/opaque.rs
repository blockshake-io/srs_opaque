use blstrs::Scalar;
use hkdf::HkdfExtract;
use rand::{CryptoRng, RngCore};
use typenum::Unsigned;

pub type Stretch = dyn Fn(&[u8]) -> Result<Digest>;

use crate::{
    ciphersuite::*,
    error::{InternalError, ProtocolError},
    keypair::{KeyPair, PublicKey, SecretKey},
    messages::{
        AuthRequest, AuthResponse, CleartextCredentials, CredentialRequest, CredentialResponse,
        Envelope, KeyExchange1, KeyExchange2, KeyExchange3, RegistrationRecord,
        RegistrationRequest, RegistrationResponse,
    },
    oprf,
    payload::Payload,
    primitives, Result,
};

/// Options for specifying custom identifiers
#[derive(Clone, Copy, Debug, Default)]
pub struct Identifiers<'a> {
    /// Client identifier
    pub client: Option<&'a [u8]>,
    /// Server identifier
    pub server: Option<&'a [u8]>,
}

pub struct ClientRegistrationFlow<'a, Payload, Rng: CryptoRng + RngCore> {
    client_identity: &'a str,
    password: &'a [u8],
    server_public_key: &'a PublicKey,
    payload: &'a Payload,
    server_identity: Option<&'a str>,
    blinding_key: Option<Scalar>,
    rng: Rng,
}

impl<'a, P, Rng> ClientRegistrationFlow<'a, P, Rng>
where
    P: Payload,
    Rng: CryptoRng + RngCore,
{
    pub fn new(
        client_identity: &'a str,
        password: &'a [u8],
        server_public_key: &'a PublicKey,
        payload: &'a P,
        server_identity: Option<&'a str>,
        rng: Rng,
    ) -> ClientRegistrationFlow<'a, P, Rng> {
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
    pub fn finish<S>(
        &self,
        response: &RegistrationResponse,
        stretch: S,
    ) -> Result<(RegistrationRecord<P>, Digest)>
    where
        S: Fn(&[u8]) -> Result<Digest>,
    {
        let blinding_key = self.blinding_key.as_ref().expect("uninitialized");
        let oprf_output = oprf::finalize(self.password, &response.evaluated_element, blinding_key)?;
        let stretched_oprf_output = stretch(&oprf_output)?;
        let randomized_pwd = primitives::extract_kdf(&[&oprf_output, &stretched_oprf_output])?;

        let mut client_rng = rand::thread_rng();
        Self::store(
            &mut client_rng,
            &randomized_pwd,
            self.server_public_key,
            self.server_identity,
            Some(&self.client_identity[..]),
            self.payload.clone(),
        )
    }

    /// Corresponds to Store
    pub fn store<R: CryptoRng + RngCore>(
        rng: &mut R,
        randomized_pwd: &Kdf,
        server_public_key: &PublicKey,
        server_identity: Option<&str>,
        client_identity: Option<&str>,
        payload: P,
    ) -> Result<(RegistrationRecord<P>, Digest)> {
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
            client_public_key: client_keypair.public_key,
            payload,
        };

        Ok((registration_record, export_key))
    }
}

pub struct ServerRegistrationFlow<'a> {
    oprf_key: &'a Scalar,
    server_public_key: &'a PublicKey,
}

impl<'a> ServerRegistrationFlow<'a> {
    pub fn new(
        oprf_key: &'a Scalar,
        server_public_key: &'a PublicKey,
    ) -> ServerRegistrationFlow<'a> {
        ServerRegistrationFlow {
            oprf_key,
            server_public_key,
        }
    }

    /// Corresponds to CreateRegistrationResponse
    pub fn start(&self, request: &RegistrationRequest) -> RegistrationResponse {
        let evaluated_element = oprf::evaluate(
            &request.blinded_element,
            request.client_identity.as_bytes(),
            self.oprf_key,
        );
        RegistrationResponse {
            evaluated_element,
            server_public_key: self.server_public_key.clone(),
        }
    }

    pub fn finish<P>(&self, _record: &RegistrationRecord<P>)
    where
        P: Payload,
    {
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
    ke1_serialized: Option<[u8; 160]>,
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
            client_public_keyshare: client_keypair.public_key,
        };
        let ke1 = KeyExchange1 {
            credential_request,
            auth_request,
        };

        self.client_secret = Some(client_keypair.secret_key);
        self.ke1_serialized = Some(ke1.serialize());

        Ok(ke1)
    }

    /// Corresponds to GenerateKE3
    pub fn finish<P: Payload, S>(
        &self,
        server_identity: Option<&str>,
        ke2: &KeyExchange2<P>,
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

    fn recover_credentials<P: Payload, S>(
        password: &[u8],
        blinding_key: &Scalar,
        response: &CredentialResponse,
        server_identity: Option<&str>,
        client_identity: &str,
        payload: &P,
        stretch: S,
    ) -> Result<(SecretKey, CleartextCredentials, PublicKey, Digest)>
    where
        S: Fn(&[u8]) -> Result<Digest>,
    {
        response.evaluated_element;
        let oprf_output = oprf::finalize(password, &response.evaluated_element, blinding_key)?;
        let stretched_oprf_output = stretch(&oprf_output)?;
        let randomized_pwd = primitives::extract_kdf(&[&oprf_output, &stretched_oprf_output])?;

        let masking_key: Digest = primitives::expand(&randomized_pwd, &[STR_MASKING_KEY])?;
        let mut xor_pad = primitives::create_credential_response_xor_pad(
            &masking_key[..],
            &response.masking_nonce[..],
        )?;

        for (x1, x2) in xor_pad.iter_mut().zip(&response.masked_response) {
            *x1 ^= x2;
        }

        let server_public_key = PublicKey::deserialize(&xor_pad[0..32])?;
        let envelope = Envelope::deserialize(&xor_pad[32..])?;

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

    fn recover<P: Payload>(
        randomized_pwd: &Kdf,
        server_public_key: &PublicKey,
        envelope: &Envelope,
        server_identity: Option<&str>,
        client_identity: Option<&str>,
        payload: &P,
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

        if envelope.auth_tag != expected_tag {
            return Err(ProtocolError::EnvelopeRecoveryError.into());
        }

        Ok((client_keypair.secret_key, cleartext_credentials, export_key))
    }

    fn auth_client_finalize<P: Payload>(
        &self,
        cleartext_credentials: &CleartextCredentials,
        client_private_key: &SecretKey,
        ke2: &KeyExchange2<P>,
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
        let ikm = [dh1, dh2, dh3].concat();

        let preamble = primitives::preamble(
            &cleartext_credentials.client_identity[..],
            ke1_serialized,
            &cleartext_credentials.server_identity[..],
            &ke2.credential_response.serialize()?[..],
            &ke2.auth_response.server_nonce,
            &ke2.auth_response.server_public_keyshare,
            &[],
        )?;
        let hashed_preamble = primitives::hash(&preamble[..])?;

        let (km2, km3, session_key) = derive_keys(&ikm[..], &hashed_preamble[..])?;
        let expected_server_mac = primitives::mac(&km2[..], &hashed_preamble[..])?;

        if ke2.auth_response.server_mac != expected_server_mac {
            return Err(ProtocolError::ServerAuthenticationError.into());
        }

        let client_mac = primitives::mac(
            &km3[..],
            &primitives::hash(&[&preamble[..], &expected_server_mac[..]].concat()[..])?[..],
        )?;

        let ke3 = KeyExchange3 { client_mac };

        Ok((ke3, session_key))
    }
}

pub struct ServerLoginFlow<'a, P>
where
    P: Payload,
{
    server_public_key: &'a PublicKey,
    server_identity: Option<&'a str>,
    ke_keypair: &'a KeyPair,
    record: &'a RegistrationRecord<P>,
    oprf_key: &'a Scalar,
    ke1: &'a KeyExchange1,
    client_identity: &'a str,
    session_key: Option<AuthCode>,
    expected_client_mac: Option<AuthCode>,
}

impl<'a, P> ServerLoginFlow<'a, P>
where
    P: Payload,
{
    pub fn new(
        server_public_key: &'a PublicKey,
        server_identity: Option<&'a str>,
        ke_keypair: &'a KeyPair,
        record: &'a RegistrationRecord<P>,
        oprf_key: &'a Scalar,
        ke1: &'a KeyExchange1,
        client_identity: &'a str,
    ) -> Self {
        Self {
            server_public_key,
            server_identity,
            ke_keypair,
            record,
            oprf_key,
            ke1,
            client_identity,
            session_key: None,
            expected_client_mac: None,
        }
    }

    /// Corresponds to GenerateKE2
    pub fn start(&mut self) -> Result<KeyExchange2<P>> {
        let mut server_rng = rand::thread_rng();
        let credential_response = Self::create_credential_response(
            &mut server_rng,
            &self.ke1.credential_request,
            self.server_public_key,
            self.record,
            self.client_identity,
            self.oprf_key,
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
            &mut server_rng,
            &cleartext_credentials,
            &self.ke_keypair.secret_key,
            &self.record.client_public_key,
            &self.ke1,
            &credential_response,
        )?;

        self.session_key = Some(session_key);
        self.expected_client_mac = Some(expected_client_mac);

        Ok(KeyExchange2 {
            credential_response,
            auth_response,
            payload: self.record.payload.clone(),
        })
    }

    /// Corresponds to GenerateKE2
    pub fn finish(&self, ke3: &KeyExchange3) -> Result<AuthCode> {
        let expected_client_mac = self.expected_client_mac.as_ref().expect("uninitialized");
        if ke3.client_mac == *expected_client_mac {
            Ok(self.session_key.expect("uninitialized"))
        } else {
            Err(ProtocolError::ServerAuthenticationError.into())
        }
    }

    fn create_credential_response<R: CryptoRng + RngCore>(
        rng: &mut R,
        request: &CredentialRequest,
        server_public_key: &PublicKey,
        record: &RegistrationRecord<P>,
        client_identity: &str,
        oprf_key: &Scalar,
    ) -> Result<CredentialResponse> {
        let evaluated_element = oprf::evaluate(
            &request.blinded_element,
            client_identity.as_bytes(),
            oprf_key,
        );

        let mut masking_nonce = Nonce::default();
        rng.fill_bytes(&mut masking_nonce);

        let xor_pad = primitives::create_credential_response_xor_pad(
            &record.masking_key,
            &masking_nonce[..],
        )?;

        let mut masked_response = Bytes::default();
        masked_response[0..32].copy_from_slice(&server_public_key.serialize()[..]);
        masked_response[32..].copy_from_slice(&record.envelope.serialize()[..]);

        for (x1, x2) in masked_response.iter_mut().zip(&xor_pad) {
            *x1 ^= x2;
        }

        Ok(CredentialResponse {
            evaluated_element,
            masking_nonce,
            masked_response,
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
        // corresponds to AuthClientStart
        let mut server_nonce = Nonce::default();
        rng.fill_bytes(&mut server_nonce);
        let mut server_keyshare_seed = Seed::default();
        rng.fill_bytes(&mut server_keyshare_seed);
        let server_keypair =
            primitives::derive_keypair(&server_keyshare_seed, STR_DERIVE_DIFFIE_HELLMAN)?;

        let preamble = primitives::preamble(
            &cleartext_credentials.client_identity[..],
            &ke1.serialize()[..],
            &cleartext_credentials.server_identity[..],
            &credential_response.serialize()?[..],
            &server_nonce[..],
            &server_keypair.public_key,
            &[],
        )?;
        let hashed_preamble = primitives::hash(&preamble[..])?;

        let dh1 = primitives::diffie_hellman(
            &server_keypair.secret_key,
            &ke1.auth_request.client_public_keyshare,
        );
        let dh2 = primitives::diffie_hellman(
            &server_secret_key,
            &ke1.auth_request.client_public_keyshare,
        );
        let dh3 = primitives::diffie_hellman(&server_keypair.secret_key, client_public_key);
        let ikm = [dh1, dh2, dh3].concat();

        let (km2, km3, session_key) = derive_keys(&ikm[..], &hashed_preamble[..])?;
        let server_mac = primitives::mac(&km2[..], &hashed_preamble[..])?;
        let expected_client_mac = primitives::mac(
            &km3[..],
            &primitives::hash(&[&preamble[..], &server_mac[..]].concat()[..])?[..],
        )?;

        let auth_response = AuthResponse {
            server_nonce,
            server_mac,
            server_public_keyshare: server_keypair.public_key,
        };

        Ok((auth_response, session_key, expected_client_mac))
    }
}

fn derive_keys(ikm: &[u8], hashed_preamble: &[u8]) -> Result<(AuthCode, AuthCode, AuthCode)> {
    let mut hkdf = HkdfExtract::<Hash>::new(None);
    hkdf.input_ikm(ikm);
    let (_, hkdf1) = hkdf.finalize();

    let handshake_secret = derive_secret(&hkdf1, STR_HANDSHAKE_SECRET, hashed_preamble)?;
    let session_key = derive_secret(&hkdf1, STR_SESSION_KEY, hashed_preamble)?;

    let hkdf2 = Kdf::from_prk(&handshake_secret[..]).map_err(|_| InternalError::HkdfError)?;
    let km2 = derive_secret(&hkdf2, STR_SERVER_MAC, b"")?;
    let km3 = derive_secret(&hkdf2, STR_CLIENT_MAC, b"")?;

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
    let client_id = ids.client.unwrap_or(&client_public_key);
    let server_id = ids.server.unwrap_or(&server_public_key);
    CleartextCredentials {
        server_public_key,
        server_identity: Vec::from(server_id),
        client_identity: Vec::from(client_id),
    }
}

fn construct_auth_tag<P: Payload>(
    auth_key: &[u8],
    cleartext_credentials: &CleartextCredentials,
    nonce: &[u8],
    payload: &P,
) -> Result<AuthCode> {
    let mut hmac = Mac::new_from_slice(&auth_key).map_err(|_| InternalError::HmacError)?;
    hmac.update(nonce);
    hmac.update(&cleartext_credentials.server_public_key);
    hmac.update(&cleartext_credentials.server_identity);
    hmac.update(&cleartext_credentials.client_identity);
    hmac.update(&payload.serialize()?);
    Ok(hmac.finalize().into_bytes())
}
