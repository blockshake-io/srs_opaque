use generic_array::GenericArray;
use typenum::{Sum, U288, U32, U64};

// provides the digest function on Hash
pub use sha2::Digest as _;
// provides the new_from_slice function on Hmac
pub use hmac::Mac as _;

pub type Hash = sha2::Sha512;
pub type Kdf = hkdf::Hkdf<Hash>;
pub type Mac = hmac::Hmac<Hash>;

/// length of a hash; corresponds to Nh in OPAQUE standard
pub type LenHash = U64;
/// length of a MAC; corresponds to Nm in OPAQUE standard
pub type LenMac = LenHash;
/// length of a seed; corresponds to Nseed in OPAQUE standard
pub type LenSeed = U32;
/// length of a nonce; corresponds to Nn in OPAQUE standard
pub type LenNonce = U32;
/// length of a public key in OPAQUE's key exchange
pub type LenKePublicKey = U32;
/// length of a secret key in OPAQUE's key exchange
pub type LenKeSecretKey = U32;
/// length of a pseudo-random key obtained from Extract
pub type LenPrk = LenHash;
/// length of a compressed element in BLS12-381's output curve
pub type LenGt = U288;

pub type LenMaskedResponse = Sum<LenKePublicKey, Sum<LenNonce, LenMac>>;
pub type LenCredentialResponse = Sum<LenGt, Sum<LenNonce, LenMaskedResponse>>;

pub type Digest = GenericArray<u8, LenHash>;
pub type Seed = GenericArray<u8, LenSeed>;
pub type Nonce = GenericArray<u8, LenNonce>;
pub type AuthCode = GenericArray<u8, LenMac>;
pub type PublicKeyBytes = GenericArray<u8, LenKePublicKey>;
pub type SecretKeyBytes = GenericArray<u8, LenKeSecretKey>;
pub type Bytes<L> = GenericArray<u8, L>;

pub const DST: &[u8] = b"opaque";

pub const STR_MASKING_KEY: &[u8; 10] = b"MaskingKey";
pub const STR_AUTH_KEY: &[u8; 7] = b"AuthKey";
pub const STR_EXPORT_KEY: &[u8; 9] = b"ExportKey";
pub const STR_PRIVATE_KEY: &[u8; 10] = b"PrivateKey";
pub const STR_DERIVE_DIFFIE_HELLMAN: &[u8; 33] = b"OPAQUE-DeriveDiffieHellmanKeyPair";
pub const STR_FINALIZE: &[u8; 8] = b"Finalize";
pub const STR_CREDENTIAL_RESPONSE_PAD: &[u8; 21] = b"CredentialResponsePad";
pub const STR_RFC: &[u8; 7] = b"RFCXXXX";
pub const STR_CLIENT_MAC: &[u8] = b"ClientMAC";
pub const STR_HANDSHAKE_SECRET: &[u8] = b"HandshakeSecret";
pub const STR_SERVER_MAC: &[u8] = b"ServerMAC";
pub const STR_SESSION_KEY: &[u8] = b"SessionKey";
pub const STR_DERIVE_KEYPAIR: &[u8; 13] = b"DeriveKeyPair";
pub const STR_CONTEXT: &[u8; 13] = b"ContextString";
