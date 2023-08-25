// provides the digest function on Hash
pub use sha2::Digest as _;
// provides the new_from_slice function on Hmac
pub use hmac::Mac as _;

pub type Hash = sha2::Sha512;
pub type Kdf = hkdf::Hkdf<Hash>;
pub type Mac = hmac::Hmac<Hash>;

pub type Digest = [u8; LEN_HASH];
pub type AuthCode = [u8; LEN_MAC];
pub type Seed = [u8; LEN_SEED];
pub type Nonce = [u8; LEN_NONCE];

/// length of a hash; corresponds to Nh in OPAQUE standard
pub const LEN_HASH: usize = 64;
/// length of a MAC; corresponds to Nm in OPAQUE standard
pub const LEN_MAC: usize = LEN_HASH;
/// length of a seed; corresponds to Nseed in OPAQUE standard
pub const LEN_SEED: usize = 32;
/// length of a nonce; corresponds to Nn in OPAQUE standard
pub const LEN_NONCE: usize = 32;
/// length of a public key in OPAQUE's key exchange
pub const LEN_KE_PK: usize = 32;
/// length of a pseudo-random key obtained from Extract
pub const LEN_PRK: usize = LEN_MAC;
pub const LEN_MASKED_RESPONSE: usize = LEN_KE_PK + LEN_NONCE + LEN_MAC;

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
