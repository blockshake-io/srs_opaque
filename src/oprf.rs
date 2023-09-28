use blstrs::{pairing, Compress, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use elliptic_curve::group::prime::PrimeCurveAffine;
use ff::Field;
use rand::{CryptoRng, RngCore};

use crate::{
    ciphersuite::*,
    error::{Error, InternalError},
    primitives::{self, i2osp_2},
    Result,
};

pub struct BlindResult {
    pub blinding_key: Scalar,
    pub blinded_element: G2Affine,
}

pub fn blind<R: CryptoRng + RngCore>(password: &[u8], rng: &mut R) -> BlindResult {
    // generate a random, non-zero blinding key. The key must be
    // non-zero as it must be inverted for unblinding
    let mut blinding_key = Scalar::ZERO;
    while blinding_key == Scalar::ZERO {
        blinding_key = Scalar::random(&mut *rng);
    }

    let element = G2Projective::hash_to_curve(password, DST, &[]);
    let blinded_element = G2Affine::from(element * blinding_key);
    BlindResult {
        blinding_key,
        blinded_element,
    }
}

pub fn blind_evaluate(blinded_element: &G2Affine, public_input: &[u8], oprf_key: &Scalar) -> Gt {
    let t = G1Projective::hash_to_curve(public_input, DST, &[]);
    let t = G1Affine::from(t);
    let x_tilde = pairing(&t, blinded_element);
    x_tilde * oprf_key
}

pub fn finalize(input: &[u8], evaluated_element: &Gt, blinding_key: &Scalar) -> Result<Digest> {
    let y = evaluated_element * primitives::invert_scalar(blinding_key)?;
    gt_to_bytes(&y, input)
}

pub fn evaluate(password: &[u8], public_input: &[u8], oprf_key: &Scalar) -> Result<Digest> {
    let blinded_element = G2Projective::hash_to_curve(password, DST, &[]);
    let blinded_element = G2Affine::from(blinded_element);
    if blinded_element == G2Affine::identity() {
        return Err(Error::Internal(InternalError::InvalidInputError));
    }

    let input = G1Projective::hash_to_curve(public_input, DST, &[]);
    let input = G1Affine::from(input);

    let evaluated_element = pairing(&input, &blinded_element) * oprf_key;

    gt_to_bytes(&evaluated_element, public_input)
}

fn gt_to_bytes(gt: &Gt, public_input: &[u8]) -> Result<Digest> {
    let mut serialized_element = Bytes::<LenGt>::default();
    gt.write_compressed(&mut serialized_element[..])
        .map_err(|_| InternalError::Custom("cannot serialize element"))?;

    Ok(Hash::new()
        .chain_update(i2osp_2(public_input.len())?)
        .chain_update(public_input)
        .chain_update(i2osp_2(serialized_element.len())?)
        .chain_update(serialized_element)
        .chain_update(STR_FINALIZE)
        .finalize()
        .try_into()
        .expect("Wrong length"))
}
