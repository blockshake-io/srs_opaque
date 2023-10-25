use crate::Result;
use generic_array::ArrayLength;

use crate::ciphersuite::Bytes;

pub trait Payload: Clone {
    type Len: ArrayLength<u8>;

    fn to_bytes(&self) -> Result<Bytes<Self::Len>>;

    fn from_bytes(buf: &Bytes<Self::Len>) -> Result<Self>;
}
