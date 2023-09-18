use base64::Engine;
use generic_array::{GenericArray, ArrayLength};

use crate::{
    Result,
    ciphersuite::Bytes, error::Error
};

pub fn b64_decode<Len>(input: &str) -> Result<GenericArray<u8, Len>>
where
    Len: ArrayLength<u8>,
{
    let mut buf = Bytes::<Len>::default();
    let data = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input).map_err(|_| Error::Internal(crate::error::InternalError::DeserializeError))?;
    if data.len() != Len::to_usize() {
        return Err(Error::Internal(crate::error::InternalError::DeserializeError));
    }
    buf.copy_from_slice(&data[..]);
    Ok(buf)
}

pub fn b64_encode(input: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}


pub mod b64_g2 {
    use blstrs::G2Affine;
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    use typenum::U96;

    pub fn serialize<S: Serializer>(v: &G2Affine, s: S) -> Result<S::Ok, S::Error> {
        String::serialize(&super::b64_encode(&v.to_compressed()), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<G2Affine, D::Error> {
        let b64 = String::deserialize(d)?;
        super::b64_decode::<U96>(&b64)
            .ok()
            .and_then(|data| {
                let buf: &[u8; 96] = data[..].try_into().unwrap();
                G2Affine::from_compressed(buf).into()
            })
            .ok_or_else(|| serde::de::Error::custom("Deserialization error for G2"))
    }
}

pub mod b64_gt {
    use blstrs::{Compress, Gt};
    use generic_array::GenericArray;
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    use crate::ciphersuite::LenGt;

    pub fn serialize<S: Serializer>(v: &Gt, s: S) -> Result<S::Ok, S::Error> {
        let mut buf = GenericArray::<u8, LenGt>::default();
        v.write_compressed(&mut buf[..])
            .map_err(|_| serde::ser::Error::custom("Serialization error for Gt"))?;
        let b64 = super::b64_encode(&buf);
        String::serialize(&b64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Gt, D::Error> {
        let buf: GenericArray<u8, LenGt> = super::b64_decode(&String::deserialize(d)?)
            .map_err(|_| serde::de::Error::custom("Deserialization error for Gt"))?;
        Gt::read_compressed(&buf[..])
            .map_err(|_| serde::de::Error::custom("Deserialization error for Gt"))
    }
}

pub mod b64_public_key {
    use crate::error;

    use generic_array::GenericArray;
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    use crate::{ciphersuite::LenKePublicKey, keypair::PublicKey};

    pub fn serialize<S: Serializer>(v: &PublicKey, s: S) -> Result<S::Ok, S::Error> {
        let b64 = super::b64_encode(&v.serialize()[..]);
        String::serialize(&b64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        decode(&String::deserialize(d)?)
            .map_err(|_| serde::de::Error::custom("Deserialization error for public key"))
    }

    pub fn decode(input: &str) -> Result<PublicKey, error::Error> {
        let buf: GenericArray<u8, LenKePublicKey> = super::b64_decode(input)?;
        Ok(PublicKey::deserialize(&buf[..])?)
    }
}

pub mod b64_digest {
    use crate::error;

    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    use crate::ciphersuite::Digest;

    pub fn serialize<S: Serializer>(v: &Digest, s: S) -> Result<S::Ok, S::Error> {
        let b64 = super::b64_encode(&v[..]);
        String::serialize(&b64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Digest, D::Error> {
        decode(&String::deserialize(d)?)
            .map_err(|_| serde::de::Error::custom("Deserialization error for digest"))
    }

    pub fn decode(input: &str) -> Result<Digest, error::Error> {
        super::b64_decode(input)
    }
}

pub mod b64_nonce {
    use crate::error;

    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    use crate::ciphersuite::Nonce;

    pub fn serialize<S: Serializer>(v: &Nonce, s: S) -> Result<S::Ok, S::Error> {
        let b64 = super::b64_encode(&v[..]);
        String::serialize(&b64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Nonce, D::Error> {
        decode(&String::deserialize(d)?)
            .map_err(|_| serde::de::Error::custom("Deserialization error for nonce"))
    }

    pub fn decode(input: &str) -> Result<Nonce, error::Error> {
        super::b64_decode(input)
    }
}

pub mod b64_auth_code {
    use crate::error;

    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    use crate::ciphersuite::AuthCode;

    pub fn serialize<S: Serializer>(v: &AuthCode, s: S) -> Result<S::Ok, S::Error> {
        let b64 = super::b64_encode(&v[..]);
        String::serialize(&b64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<AuthCode, D::Error> {
        decode(&String::deserialize(d)?)
            .map_err(|_| serde::de::Error::custom("Deserialization error for auth_code"))
    }

    pub fn decode(input: &str) -> Result<AuthCode, error::Error> {
        super::b64_decode(input)
    }
}

pub mod b64_envelope {
    use crate::error;

    use generic_array::GenericArray;
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    use crate::{ciphersuite::LenEnvelope, messages::Envelope};

    pub fn serialize<S: Serializer>(v: &Envelope, s: S) -> Result<S::Ok, S::Error> {
        let b64 = super::b64_encode(&v.serialize());
        String::serialize(&b64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Envelope, D::Error> {
        decode(&String::deserialize(d)?)
            .map_err(|_| serde::de::Error::custom("Deserialization error for envelope"))
    }

    pub fn decode(input: &str) -> Result<Envelope, error::Error> {
        let buf: GenericArray<u8, LenEnvelope> = super::b64_decode(input)?;
        Ok(Envelope::deserialize(&buf[..])?)
    }
}

pub mod b64_masked_response {
    use crate::error;

    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    use crate::ciphersuite::{Bytes, LenMaskedResponse};

    pub fn serialize<S: Serializer>(v: &Bytes<LenMaskedResponse>, s: S) -> Result<S::Ok, S::Error> {
        let b64 = super::b64_encode(&v[..]);
        String::serialize(&b64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Bytes<LenMaskedResponse>, D::Error> {
        decode(&String::deserialize(d)?)
            .map_err(|_| serde::de::Error::custom("Deserialization error for masked_response"))
    }

    pub fn decode(input: &str) -> Result<Bytes<LenMaskedResponse>, error::Error> {
        super::b64_decode(input)
    }
}