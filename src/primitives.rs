use curve25519_dalek::{scalar::Scalar, RistrettoPoint};

use crate::{
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
    ExpandMsgXmd::<sha2::Sha512>::expand_message(input, dst, 64)
        .map_err(|_| InternalError::Custom("cannot expand message (XMD)"))?
        .fill_bytes(&mut uniform_bytes);

    Ok(Scalar::from_bytes_mod_order_wide(&uniform_bytes.into()))
}

pub fn i2osp_2(input: usize) -> Result<[u8; 2], InternalError> {
    u16::try_from(input)
        .map(|input| input.to_be_bytes())
        .map_err(|_| InternalError::Custom("could not compute i2osp_2"))
}
