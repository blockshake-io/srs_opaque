use blstrs::{pairing, Compress, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use ff::Field;
use hkdf::{Hkdf, HkdfExtract};
use sha2::{Digest, Sha512};

use crate::{
    error::InternalError,
    messages::{RegistrationRequest, RegistrationResponse},
};

pub const G2_LEN: u32 = 96;
pub const OPRF_LEN: usize = 64;
pub const HASH_LEN: usize = OPRF_LEN;
pub const DST: &[u8] = b"opaque";

pub type Hash = [u8; HASH_LEN];

pub struct BlindResult {
    pub blinding_key: Scalar,
    pub blinded_element: G2Affine,
}

pub struct ClientRegistrationFlow {
    blinding_key: Scalar,
}

impl ClientRegistrationFlow {
    pub fn start(username: &str, password: &str) -> (Self, RegistrationRequest) {
        let result = Self::oprf_blind(password.as_bytes());
        (
            ClientRegistrationFlow {
                blinding_key: result.blinding_key,
            },
            RegistrationRequest {
                username: username.to_string(),
                blinded_element: result.blinded_element,
            },
        )
    }

    pub fn finish(&self, response: &RegistrationResponse) -> Result<[u8; 32], InternalError> {
        let oprf_output = Self::oprf_finalize(&response.evaluated_element, &self.blinding_key)?;
        let (randomized_pwd, randomized_pwd_hasher) = Self::derive_key(&oprf_output)?;

        todo!();
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
        evaluated_element: &Gt,
        blinding_key: &Scalar,
    ) -> Result<[u8; OPRF_LEN], InternalError> {
        let y = evaluated_element * Self::invert_scalar(blinding_key)?;
        let mut bytes = Vec::new();
        y.write_compressed(&mut bytes).unwrap();
        let hash: [u8; HASH_LEN] = Sha512::digest(bytes)
            .as_slice()
            .try_into()
            .expect("Wrong length");
        Ok(hash)
    }

    pub fn invert_scalar(scalar: &Scalar) -> Result<Scalar, InternalError> {
        let inverted = scalar.invert();
        if bool::from(inverted.is_some()) {
            Ok(inverted.unwrap())
        } else {
            Err(InternalError::Custom("cannot invert scalar"))
        }
    }

    pub fn stretch(input: &[u8]) -> Result<Hash, InternalError> {
        let argon2 = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(1024, 1, 1, Some(OPRF_LEN)).unwrap(),
        );
        let mut output = [0; OPRF_LEN];
        argon2
            .hash_password_into(&input, &[0; argon2::RECOMMENDED_SALT_LEN], &mut output)
            .map_err(|_| InternalError::KsfError)?;
        Ok(output)
    }

    pub fn derive_key(oprf_output: &[u8]) -> Result<(Hash, Hkdf<Sha512>), InternalError> {
        let stretched_oprf_output = Self::stretch(&oprf_output)?;

        let mut hkdf = HkdfExtract::<Sha512>::new(None);
        hkdf.input_ikm(&oprf_output);
        hkdf.input_ikm(&stretched_oprf_output);
        let (randomized_pwd, randomized_pwd_hasher) = hkdf.finalize();

        let randomized_pwd: Hash = randomized_pwd
            .as_slice()
            .try_into()
            .map_err(|_| InternalError::Custom("cannot convert HKDF output to array"))?;

        Ok((randomized_pwd, randomized_pwd_hasher))
    }
}

pub struct ServerRegistrationFlow;

impl ServerRegistrationFlow {
    pub fn create_registration_response(request: &RegistrationRequest, oprf_key: &Scalar) -> Gt {
        let t = G1Projective::hash_to_curve(request.username.as_bytes(), DST, &[]);
        let t = G1Affine::from(t);
        let x_tilde = pairing(&t, &request.blinded_element);
        x_tilde * oprf_key
    }
}
