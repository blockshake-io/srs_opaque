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
    /// Could not compute a hash
    HashError,
    /// Could not serialize an object
    SerializeError,
    /// Could not de-serialize an object
    DeserializeError,
    /// Could not recover envelope
    EnvelopeRecoveryError,
    /// Could not authenticate user at server
    ServerAuthenticationError,
}
