use blstrs::Scalar;
use hkdf::HkdfExtract;
use rand::{CryptoRng, RngCore};

use crate::{
    ciphersuite::*,
    error::{InternalError, ProtocolError},
    keypair::{KeyPair, PublicKey, SecretKey},
    messages::{
        AuthRequest, AuthResponse, CleartextCredentials, CredentialRequest, CredentialResponse,
        Envelope, KeyExchange1, KeyExchange2, KeyExchange3, RegistrationRecord,
        RegistrationRequest, RegistrationResponse,
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

pub struct ClientRegistrationFlow<'a> {
    username: &'a str,
    password: &'a [u8],
    server_public_key: &'a PublicKey,
    server_identity: Option<&'a str>,
    blinding_key: Option<Scalar>,
}

impl<'a> ClientRegistrationFlow<'a> {
    pub fn new(
        username: &'a str,
        password: &'a [u8],
        server_public_key: &'a PublicKey,
        server_identity: Option<&'a str>,
    ) -> ClientRegistrationFlow<'a> {
        ClientRegistrationFlow {
            username,
            password,
            server_public_key,
            server_identity,
            blinding_key: None,
        }
    }

    pub fn start(&mut self) -> RegistrationRequest {
        let result = oprf::blind(self.password);
        self.blinding_key = Some(result.blinding_key);
        RegistrationRequest {
            username: self.username.to_string(),
            blinded_element: result.blinded_element,
        }
    }

    pub fn finish(&self, response: &RegistrationResponse) -> Result<(RegistrationRecord, Digest)> {
        let blinding_key = self.blinding_key.as_ref().expect("uninitialized");
        let oprf_output = oprf::finalize(self.password, &response.evaluated_element, blinding_key)?;
        let (_, randomized_pwd_hasher) = primitives::derive_key(&oprf_output)?;

        let mut client_rng = rand::thread_rng();
        Self::store(
            &mut client_rng,
            &randomized_pwd_hasher,
            self.server_public_key,
            self.server_identity,
            Some(&self.username[..]),
        )
    }

    pub fn store<R: CryptoRng + RngCore>(
        rng: &mut R,
        randomized_pwd: &Kdf,
        server_public_key: &PublicKey,
        server_identity: Option<&str>,
        client_identity: Option<&str>,
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
            &server_public_key,
            &client_keypair.public_key,
        );

        let aad = [&nonce, &cleartext_credentials.serialize()[..]].concat();

        let mut hmac = Mac::new_from_slice(&auth_key).map_err(|_| InternalError::HmacError)?;
        hmac.update(&aad);
        let auth_tag = hmac.finalize().into_bytes().into();

        let registration_record = RegistrationRecord {
            envelope: Envelope { nonce, auth_tag },
            masking_key,
            client_public_key: client_keypair.public_key,
        };

        Ok((registration_record, export_key))
    }
}

pub struct ServerRegistrationFlow<'a> {
    oprf_key: &'a Scalar,
}

impl<'a> ServerRegistrationFlow<'a> {
    pub fn new(oprf_key: &'a Scalar) -> ServerRegistrationFlow {
        ServerRegistrationFlow { oprf_key }
    }

    pub fn start(&self, request: &RegistrationRequest) -> RegistrationResponse {
        Self::create_registration_response(request, &self.oprf_key)
    }

    pub fn finish(&self, _record: &RegistrationRecord) {
        // we need to decide what to do here
    }

    pub fn create_registration_response(
        request: &RegistrationRequest,
        oprf_key: &Scalar,
    ) -> RegistrationResponse {
        let evaluated_element = oprf::evaluate(
            &request.blinded_element,
            request.username.as_bytes(),
            oprf_key,
        );
        RegistrationResponse { evaluated_element }
    }
}

pub struct ClientLoginFlow<'a> {
    username: &'a str,
    password: &'a [u8],
    blinding_key: Option<Scalar>,
    client_secret: Option<SecretKey>,
    ke1_serialized: Option<[u8; 160]>,
}

impl<'a> ClientLoginFlow<'a> {
    pub fn new(username: &'a str, password: &'a [u8]) -> ClientLoginFlow<'a> {
        ClientLoginFlow {
            username,
            password,
            blinding_key: None,
            client_secret: None,
            ke1_serialized: None,
        }
    }

    /// Corresponds to GenerateKE1
    pub fn start<R: CryptoRng + RngCore>(&mut self, rng: &mut R) -> Result<KeyExchange1> {
        // corresponds to CreateCredentialRequest
        let blind_result = oprf::blind(self.password);
        self.blinding_key = Some(blind_result.blinding_key);
        let credential_request = CredentialRequest {
            blinded_element: blind_result.blinded_element,
        };

        // corresponds to AuthClientStart
        let mut client_nonce = [0; LEN_NONCE];
        rng.fill_bytes(&mut client_nonce);
        let mut client_keyshare_seed = [0; LEN_SEED];
        rng.fill_bytes(&mut client_keyshare_seed);
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
    pub fn finish(
        &self,
        server_identity: Option<&str>,
        ke2: &KeyExchange2,
    ) -> Result<(KeyExchange3, AuthCode, Digest)> {
        let blinding_key = &self.blinding_key.expect("uninitialized");

        let (client_private_key, cleartext_credentials, _, export_key) = Self::recover_credentials(
            self.password,
            blinding_key,
            &ke2.credential_response,
            server_identity,
            self.username,
        )?;

        let (ke3, session_key) =
            self.auth_client_finalize(&cleartext_credentials, &client_private_key, &ke2)?;

        Ok((ke3, session_key, export_key))
    }

    fn recover_credentials(
        password: &[u8],
        blinding_key: &Scalar,
        response: &CredentialResponse,
        server_identity: Option<&str>,
        username: &str,
    ) -> Result<(SecretKey, CleartextCredentials, PublicKey, Digest)> {
        response.evaluated_element;
        let oprf_output = oprf::finalize(password, &response.evaluated_element, blinding_key)?;
        let (_, randomized_pwd) = primitives::derive_key(&oprf_output)?;

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
            Some(username),
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

        let aad = [&envelope.nonce, &cleartext_credentials.serialize()[..]].concat();

        let mut hmac = Mac::new_from_slice(&auth_key).map_err(|_| InternalError::HmacError)?;
        hmac.update(&aad);
        let expected_tag: AuthCode = hmac.finalize().into_bytes().into();

        if envelope.auth_tag != expected_tag {
            return Err(ProtocolError::EnvelopeRecoveryError.into());
        }

        Ok((client_keypair.secret_key, cleartext_credentials, export_key))
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

pub struct ServerLoginFlow<'a> {
    server_public_key: &'a PublicKey,
    server_identity: Option<&'a str>,
    ke_keypair: &'a KeyPair,
    record: &'a RegistrationRecord,
    oprf_key: &'a Scalar,
    ke1: &'a KeyExchange1,
    username: &'a str,
    session_key: Option<AuthCode>,
    expected_client_mac: Option<AuthCode>,
}

impl<'a> ServerLoginFlow<'a> {
    pub fn new(
        server_public_key: &'a PublicKey,
        server_identity: Option<&'a str>,
        ke_keypair: &'a KeyPair,
        record: &'a RegistrationRecord,
        oprf_key: &'a Scalar,
        ke1: &'a KeyExchange1,
        username: &'a str,
    ) -> Self {
        Self {
            server_public_key,
            server_identity,
            ke_keypair,
            record,
            oprf_key,
            ke1,
            username,
            session_key: None,
            expected_client_mac: None,
        }
    }

    /// Corresponds to GenerateKE2
    pub fn start(&mut self) -> Result<KeyExchange2> {
        let mut server_rng = rand::thread_rng();
        let credential_response = Self::create_credential_response(
            &mut server_rng,
            &self.ke1.credential_request,
            self.server_public_key,
            self.record,
            self.username,
            self.oprf_key,
        )?;

        let ids = Identifiers {
            client: Some(self.username.as_bytes()),
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
        record: &RegistrationRecord,
        username: &str,
        oprf_key: &Scalar,
    ) -> Result<CredentialResponse> {
        let evaluated_element =
            oprf::evaluate(&request.blinded_element, username.as_bytes(), oprf_key);

        let mut masking_nonce = Nonce::default();
        rng.fill_bytes(&mut masking_nonce);

        let xor_pad = primitives::create_credential_response_xor_pad(
            &record.masking_key,
            &masking_nonce[..],
        )?;

        let mut masked_response = [0; LEN_MASKED_RESPONSE];
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
    let len_extract = primitives::i2osp_2(LEN_PRK)?;
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
