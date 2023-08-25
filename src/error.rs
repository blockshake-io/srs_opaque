use core::fmt::Debug;
use std::fmt::Display;

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
}
#[derive(Debug)]
pub enum ProtocolError {
    /// Could not recover envelope
    EnvelopeRecoveryError,
    /// Could not authenticate user at server
    ServerAuthenticationError,
}

#[derive(Debug)]
pub enum Error {
    Protocol(ProtocolError),
    Internal(InternalError),
}

impl std::fmt::Display for InternalError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            InternalError::Custom(err) => write!(f, "Custom error: {:?}", err),
            InternalError::KsfError => write!(f, "KsfError"),
            InternalError::HkdfError => write!(f, "HkdfError"),
            InternalError::HmacError => write!(f, "HmacError"),
            InternalError::DeriveKeyError => write!(f, "DeriveKeyError"),
            InternalError::HashError => write!(f, "HashError"),
            InternalError::SerializeError => write!(f, "SerializeError"),
            InternalError::DeserializeError => write!(f, "DeserializeError"),
        }
    }
}

impl std::error::Error for InternalError {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        None
    }
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            ProtocolError::EnvelopeRecoveryError => write!(f, "EnvelopeRecoveryError"),
            ProtocolError::ServerAuthenticationError => write!(f, "ServerAuthenticationError"),
        }
    }
}

impl std::error::Error for ProtocolError {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        None
    }
}

impl From<ProtocolError> for Error {
    fn from(err: ProtocolError) -> Error {
        Error::Protocol(err)
    }
}

impl From<InternalError> for Error {
    fn from(err: InternalError) -> Error {
        Error::Internal(err)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::Internal(ref err) => Display::fmt(&err, f),
            Error::Protocol(ref err) => Display::fmt(&err, f),
        }
    }
}

impl std::error::Error for Error {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        match *self {
            Error::Internal(ref err) => Some(err),
            Error::Protocol(ref err) => Some(err),
        }
    }
}
