// use crate::{util, EvaluatedElement, PoprfError};
use crate::{
    error::{Error, InternalError},
    serialization, Result,
};
use blstrs::{Gt, Scalar};
use elliptic_curve::group::Group;
use ff::Field;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct EvaluatedElement {
    pub server_id: u64,
    #[serde(with = "serialization::b64_gt")]
    pub evaluated_element: Gt,
}

pub fn lagrange_coefficient(j: u64, share_set: &[u64]) -> Scalar {
    let mut result = Scalar::ONE;
    let j = Scalar::from(j);
    for jp in share_set.iter().map(|x| Scalar::from(*x)) {
        if j != jp {
            let numerator = -jp;
            let denumerator = j - jp;
            result *= numerator * denumerator.invert().unwrap();
        }
    }
    result
}

// This is based on Corollary 22.2 (Interpolation in the exponent) of Boneh's & Shoup's book
pub fn lagrange_interpolation(threshold: u16, parts: &[EvaluatedElement]) -> Result<Gt> {
    let threshold = threshold as usize;
    if parts.len() < threshold {
        return Err(Error::Internal(InternalError::ShamirSharingError));
    }

    let parts = &parts[0..threshold];
    let share_indexes: Vec<u64> = parts.iter().map(|x| x.server_id).collect();

    Ok(parts.iter().fold(Gt::identity(), |acc, x| {
        let lambda = lagrange_coefficient(x.server_id, &share_indexes[..]);
        acc + (x.evaluated_element * lambda)
    }))
}
