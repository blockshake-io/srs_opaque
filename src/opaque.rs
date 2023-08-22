use blstrs::{pairing, Compress, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use ff::Field;
use hkdf::HkdfExtract;
use rand::{CryptoRng, RngCore};

use crate::{
    ciphersuite::*,
    error::InternalError,
    keypair::PublicKey,
    messages::{RegistrationRequest, RegistrationResponse},
    primitives::{self, i2osp_2},
};

///////////////
// Constants //
// ========= //
///////////////

const STR_MASKING_KEY: &[u8; 10] = b"MaskingKey";
const STR_AUTH_KEY: &[u8; 7] = b"AuthKey";
const STR_EXPORT_KEY: &[u8; 9] = b"ExportKey";
const STR_PRIVATE_KEY: &[u8; 10] = b"PrivateKey";
const STR_DERIVE_DIFFIE_HELLMAN: &[u8; 33] = b"OPAQUE-DeriveDiffieHellmanKeyPair";
const STR_FINALIZE: [u8; 8] = *b"Finalize";

/// Options for specifying custom identifiers
#[derive(Clone, Copy, Debug, Default)]
pub struct Identifiers<'a> {
    /// Client identifier
    pub client: Option<&'a [u8]>,
    /// Server identifier
    pub server: Option<&'a [u8]>,
}

pub struct CleartextCredentials {
    pub server_public_key: [u8; LEN_KE_PK],
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
    pub nonce: Digest,
    pub auth_tag: AuthCode,
}

pub struct RegistrationRecord {
    pub envelope: Envelope,
    pub masking_key: Digest,
    pub client_public_key: PublicKey,
}

pub struct BlindResult {
    pub blinding_key: Scalar,
    pub blinded_element: G2Affine,
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
            username: username,
            password: password,
            server_public_key,
            server_identity,
            blinding_key: None,
        }
    }

    pub fn start(&mut self) -> RegistrationRequest {
        let result = Self::oprf_blind(self.password);
        self.blinding_key = Some(result.blinding_key);
        RegistrationRequest {
            username: self.username.to_string(),
            blinded_element: result.blinded_element,
        }
    }

    pub fn finish(
        &self,
        response: &RegistrationResponse,
    ) -> Result<(RegistrationRecord, Digest), InternalError> {
        let blinding_key = &self
            .blinding_key
            .ok_or(InternalError::Custom("not initialized"))?;
        let oprf_output =
            Self::oprf_finalize(self.password, &response.evaluated_element, blinding_key)?;
        let (_, randomized_pwd_hasher) = Self::derive_key(&oprf_output)?;

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
    ) -> Result<(RegistrationRecord, Digest), InternalError> {
        let mut nonce: Digest = [0; LEN_HASH];
        rng.fill_bytes(&mut nonce);

        let masking_key: Digest = Self::expand(randomized_pwd, STR_MASKING_KEY)?;
        let auth_key: Digest = Self::expand_multi(randomized_pwd, &[&nonce, STR_AUTH_KEY])?;
        let export_key: Digest = Self::expand_multi(randomized_pwd, &[&nonce, STR_EXPORT_KEY])?;
        let seed: Digest = Self::expand_multi(randomized_pwd, &[&nonce, STR_PRIVATE_KEY])?;

        let client_keypair = primitives::derive_keypair(&seed, STR_DERIVE_DIFFIE_HELLMAN)?;

        let identifiers = Identifiers {
            client: client_identity.map(|x| x.as_bytes()),
            server: server_identity.map(|x| x.as_bytes()),
        };
        let cleartext_credentials = Self::create_cleartext_credentials(
            &identifiers,
            &server_public_key,
            &client_keypair.public_key,
        );

        let aad = [&nonce[..], &cleartext_credentials.serialize()[..]].concat();

        let mut hmac = Mac::new_from_slice(&auth_key[..]).map_err(|_| InternalError::HmacError)?;
        hmac.update(&aad[..]);
        let auth_tag = hmac.finalize().into_bytes().into();

        let envelope = Envelope {
            nonce: nonce,
            auth_tag: auth_tag,
        };

        let registration_record = RegistrationRecord {
            envelope,
            masking_key,
            client_public_key: client_keypair.public_key,
        };

        Ok((registration_record, export_key))
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

    pub fn oprf_blind(password: &[u8]) -> BlindResult {
        // generate a random, non-zero blinding key. The key must be
        // non-zero as it must be inverted for unblinding
        let mut blinding_key = Scalar::ZERO;
        while blinding_key == Scalar::ZERO {
            blinding_key = Scalar::random(rand::thread_rng());
        }

        let element = G2Projective::hash_to_curve(password, DST, &[]);
        let blinded_element = G2Affine::from(element * blinding_key);
        BlindResult {
            blinding_key,
            blinded_element,
        }
    }

    pub fn oprf_finalize(
        input: &[u8],
        evaluated_element: &Gt,
        blinding_key: &Scalar,
    ) -> Result<Digest, InternalError> {
        let y = evaluated_element * Self::invert_scalar(blinding_key)?;
        let mut serialized_element = Vec::new();
        y.write_compressed(&mut serialized_element)
            .map_err(|_| InternalError::Custom("cannot serialize element"))?;

        Ok(Hash::new()
            .chain_update(i2osp_2(input.len())?)
            .chain_update(input)
            .chain_update(i2osp_2(serialized_element.len())?)
            .chain_update(serialized_element)
            .chain_update(STR_FINALIZE)
            .finalize()
            .try_into()
            .expect("Wrong length"))
    }

    pub fn invert_scalar(scalar: &Scalar) -> Result<Scalar, InternalError> {
        let inverted = scalar.invert();
        if bool::from(inverted.is_some()) {
            Ok(inverted.unwrap())
        } else {
            Err(InternalError::Custom("cannot invert scalar"))
        }
    }

    pub fn stretch(input: &[u8]) -> Result<Digest, InternalError> {
        let argon2 = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(1024, 1, 1, Some(LEN_HASH)).unwrap(),
        );
        let mut output = [0; LEN_HASH];
        argon2
            .hash_password_into(&input, &[0; argon2::RECOMMENDED_SALT_LEN], &mut output)
            .map_err(|_| InternalError::KsfError)?;
        Ok(output)
    }

    pub fn derive_key(oprf_output: &[u8]) -> Result<(Digest, Kdf), InternalError> {
        let stretched_oprf_output = Self::stretch(&oprf_output)?;

        let mut hkdf = HkdfExtract::<Hash>::new(None);
        hkdf.input_ikm(&oprf_output);
        hkdf.input_ikm(&stretched_oprf_output);
        let (randomized_pwd, randomized_pwd_hasher) = hkdf.finalize();

        let randomized_pwd: Digest = randomized_pwd
            .as_slice()
            .try_into()
            .map_err(|_| InternalError::Custom("cannot convert HKDF output to array"))?;

        Ok((randomized_pwd, randomized_pwd_hasher))
    }

    pub fn expand(hkdf: &Kdf, info: &[u8]) -> Result<Digest, InternalError> {
        Self::expand_multi(hkdf, &[info])
    }

    pub fn expand_multi(hkdf: &Kdf, info: &[&[u8]]) -> Result<Digest, InternalError> {
        let mut buf: Digest = [0; LEN_HASH];
        hkdf.expand_multi_info(info, &mut buf[..])
            .map_err(|_| InternalError::HkdfError)?;
        Ok(buf)
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
        let t = G1Projective::hash_to_curve(request.username.as_bytes(), DST, &[]);
        let t = G1Affine::from(t);
        let x_tilde = pairing(&t, &request.blinded_element);
        RegistrationResponse {
            evaluated_element: x_tilde * oprf_key,
        }
    }
}
