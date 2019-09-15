use std::error;
use std::fmt;
use std::net::SocketAddr;
use std::io;
use std::convert::From;

use crate::auth::AuthMethod;

/// Returned in case negotiating a proxy connection with a client fails for whatever reason.
#[derive(Debug)]
pub enum SOCKSError {
    NoOverlappingAuthMethodsError(SocketAddr, Vec<AuthMethod>, Vec<AuthMethod>),
    UnknownAuthMethodSubnegotiationVersionError(SocketAddr, u8, u8),
    WrongCredentialsError(SocketAddr), // Don't store or log the credentials for security reasons
    ProtoolVersionError(SocketAddr, u8),
    UnknownRequestCommandError(SocketAddr, u8),
    UnknownAddressTypeError(SocketAddr, u8),
    UnknownReservedByteError(SocketAddr, u8),
    UnknownProtocolViolationError(SocketAddr, String),
    NoAuthMethodsError(SocketAddr),
    TimeoutError(SocketAddr),
    StreamIOError(io::Error),
}

impl fmt::Display for SOCKSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SOCKSError::NoOverlappingAuthMethodsError(client_addr, client_methods, server_methods) => {
                write!(f, "Could not negotiate authentication method with client '{}': client supports {:?}, we support {:?}", client_addr, client_methods, server_methods)
            },

            SOCKSError::ProtoolVersionError(client_addr, requested_version) => {
                write!(f, "Client '{}' requested protocol version {}, but only 5 is supported", client_addr, requested_version)
            },

            SOCKSError::UnknownAuthMethodSubnegotiationVersionError(client_addr, requested_version, supported_version) => {
                write!(f, "Client '{}' requested auth subnegotiation version {}, but only {} is supported", client_addr, requested_version, supported_version)
            }

            SOCKSError::UnknownAddressTypeError(client_addr, atyp) => {
                write!(f, "Client '{}' requested unknown address type {}", client_addr, atyp)
            },

            SOCKSError::UnknownRequestCommandError(client_addr, requested_command) => {
                write!(f, "Client '{}' requested an unknown SOCKS command '{}'", client_addr, requested_command)
            },
            SOCKSError::UnknownReservedByteError(client_addr, reserved_byte) => {
                write!(f, "Client '{}' sent an unknown SOCKS reserved byte '{}' in request", client_addr, reserved_byte)
            },

            SOCKSError::UnknownProtocolViolationError(client_addr, err) => {
                write!(f, "Client '{}' violated the SOCKS5 protocol: {}", client_addr, err)
            },
            SOCKSError::NoAuthMethodsError(client_addr) => {
                write!(f, "Client '{}' did not send any supported auth methods", client_addr)
            },
            SOCKSError::TimeoutError(client_addr) => {
                write!(f, "Client '{}' timed out", client_addr)
            },
            SOCKSError::StreamIOError(e) => {
                write!(f, "Failed to send data due to an IO error: {}", e)
            },
            SOCKSError::WrongCredentialsError(client_addr) => {
                write!(f, "Client '{}' supplied invalid credentials", client_addr)
            }
        }
    }
}

// This is important for other errors to wrap this one.
// TODO: Proper implementation
impl error::Error for SOCKSError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

impl From<io::Error> for SOCKSError {
    fn from(item: io::Error) -> Self {
        return SOCKSError::StreamIOError(item);
    }
}