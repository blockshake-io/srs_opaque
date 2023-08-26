use crate::Result;
use generic_array::ArrayLength;

use crate::ciphersuite::Bytes;

pub trait Payload: Clone {
    type Len: ArrayLength<u8>;

    fn serialize(&self) -> Result<Bytes<Self::Len>>;

    fn deserialize(buf: &Bytes<Self::Len>) -> Result<Self>
    where
        Self: Sized;
}