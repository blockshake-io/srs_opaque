// provides the digest function on Hash
pub use sha2::Digest as _;
// provides the new_from_slice function on Hmac
pub use hmac::Mac as _;

pub type Hash = sha2::Sha512;
pub type Kdf = hkdf::Hkdf<Hash>;
pub type Mac = hmac::Hmac<Hash>;

pub type Digest = [u8; LEN_HASH];
pub type AuthCode = [u8; LEN_MAC];

pub const LEN_HASH: usize = 64;
pub const LEN_MAC: usize = LEN_HASH;
pub const LEN_KE_PK: usize = 32;

pub const DST: &[u8] = b"opaque";
