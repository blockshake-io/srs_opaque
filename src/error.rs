use core::fmt::Debug;

#[derive(Debug)]
pub enum InternalError {
    /// Custom error
    Custom(&'static str),
    /// Key-stretching error
    KsfError,
    /// Key-derivation error
    HkdfError,
    /// Message-authentication code error
    HmacError,
    /// Could not derive a key
    DeriveKeyError,
}
