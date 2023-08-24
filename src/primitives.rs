use curve25519_dalek::{scalar::Scalar, RistrettoPoint};
use ff::Field;
use hkdf::HkdfExtract;

use crate::{
    ciphersuite::*,
    error::InternalError,
    keypair::{KeyPair, PublicKey, SecretKey},
};
use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};

const STR_DERIVE_KEYPAIR: &[u8; 13] = b"DeriveKeyPair";
const STR_CONTEXT: &[u8; 13] = b"ContextString";

pub fn derive_keypair(seed: &[u8], info: &[u8]) -> Result<KeyPair, InternalError> {
    let info_len = self::i2osp_2(info.len())?;
    let mut sk_s = Scalar::ZERO;

    let counter = 0;
    while sk_s == Scalar::ZERO {
        if counter > 255 {
            return Err(InternalError::DeriveKeyError);
        }

        let counter_bytes = i2osp_2(counter)?;
        sk_s = hash_to_scalar(
            &[seed, &info_len, info, &counter_bytes],
            &[STR_DERIVE_KEYPAIR, STR_CONTEXT],
        )?;
    }

    Ok(KeyPair {
        secret_key: SecretKey(sk_s),
        public_key: PublicKey(RistrettoPoint::mul_base(&sk_s)),
    })
}

// Implements the `HashToScalar()` function from
// https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-07.html#section-4.1
fn hash_to_scalar(input: &[&[u8]], dst: &[&[u8]]) -> Result<Scalar, InternalError> {
    let mut uniform_bytes: [u8; 64] = [0; 64];
    ExpandMsgXmd::<Hash>::expand_message(input, dst, 64)
        .map_err(|_| InternalError::Custom("cannot expand message (XMD)"))?
        .fill_bytes(&mut uniform_bytes);

    Ok(Scalar::from_bytes_mod_order_wide(&uniform_bytes.into()))
}

pub fn i2osp_2(input: usize) -> Result<[u8; 2], InternalError> {
    u16::try_from(input)
        .map(|input| input.to_be_bytes())
        .map_err(|_| InternalError::Custom("could not compute i2osp_2"))
}

pub fn invert_scalar(scalar: &blstrs::Scalar) -> Result<blstrs::Scalar, InternalError> {
    let inverted = scalar.invert();
    if bool::from(inverted.is_some()) {
        Ok(inverted.unwrap())
    } else {
        Err(InternalError::Custom("cannot invert scalar"))
    }
}

pub fn expand64(hkdf: &Kdf, info: &[&[u8]]) -> Result<[u8; 64], InternalError> {
    let mut buf = [0; 64];
    hkdf.expand_multi_info(info, &mut buf[..])
        .map_err(|_| InternalError::HkdfError)?;
    Ok(buf)
}

pub fn expand32(hkdf: &Kdf, info: &[&[u8]]) -> Result<[u8; 32], InternalError> {
    let mut buf = [0; 32];
    hkdf.expand_multi_info(info, &mut buf[..])
        .map_err(|_| InternalError::HkdfError)?;
    Ok(buf)
}

pub fn hash(input: &[u8]) -> Result<Digest, InternalError> {
    let digest = Hash::digest(input);
    Ok(digest
        .as_slice()
        .try_into()
        .map_err(|_| InternalError::HashError)?)
}

pub fn mac(key: &[u8], msg: &[u8]) -> Result<AuthCode, InternalError> {
    let mut mac_hasher = Mac::new_from_slice(key).map_err(|_| InternalError::HmacError)?;
    mac_hasher.update(msg);
    Ok(mac_hasher
        .finalize()
        .into_bytes()
        .try_into()
        .map_err(|_| InternalError::HmacError)?)
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
    let stretched_oprf_output = stretch(&oprf_output)?;

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

pub fn create_credential_response_xor_pad(
    masking_key: &[u8],
    masking_nonce: &[u8],
) -> Result<[u8; LEN_MASKED_RESPONSE], InternalError> {
    let mut xor_pad = [0; LEN_MASKED_RESPONSE];
    Kdf::from_prk(masking_key)
        .map_err(|_| InternalError::HkdfError)?
        .expand_multi_info(&[masking_nonce, STR_CREDENTIAL_RESPONSE_PAD], &mut xor_pad)
        .map_err(|_| InternalError::HkdfError)?;
    Ok(xor_pad)
}

pub fn diffie_hellman(secret_key: &SecretKey, public_key: &PublicKey) -> [u8; LEN_KE_PK] {
    let dh = secret_key.0 * public_key.0;
    dh.compress().to_bytes()
}

pub fn preamble(
    username: &[u8],
    ke1_message: &[u8],
    server_identity: &[u8],
    credential_response: &[u8],
    server_nonce: &[u8],
    server_public_keyshare: &PublicKey,
    context: &[u8],
) -> Result<Vec<u8>, InternalError> {
    let len_context = i2osp_2(context.len())?;
    let len_username = i2osp_2(username.len())?;
    let len_server_identity = i2osp_2(server_identity.len())?;
    Ok([
        &STR_RFC[..],
        &len_context[..],
        context,
        &len_username[..],
        username,
        ke1_message,
        &len_server_identity[..],
        &server_identity[..],
        credential_response,
        server_nonce,
        &server_public_keyshare.serialize()[..],
    ]
    .concat())
}
