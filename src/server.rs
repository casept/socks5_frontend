use std::io;
use std::net;
use std::time;

use crate::auth::AuthMethod;
use crate::connection::UnrequitedSOCKSConnection;
use crate::socks_error::SOCKSError;

/// A SOCKSServer's function is to accept and negotiate connections from clients.
/// However, actually forwarding/modifying client data is out of scope for this library,
/// and is left to the consumer.
pub struct SOCKSServer {
    listener: net::TcpListener,
    timeout: Option<time::Duration>,
    auth_methods: Vec<AuthMethod>,
    username: Option<String>,
    password: Option<String>,
}

impl SOCKSServer {
    /// Creates a new SOCKS5 server listening for connections on `bind_addr`.
    /// This function will fail if it fails to bind to `bind_addr`.
    ///
    /// For production use it's highly recommended to set a `timeout`.
    /// If the passed timeout is not `None` it will be set as the timeout for both reads and writes on client streams.
    /// If the passed timeout is `None` no timeout is set.
    /// Passing a 0 timeout will cause a panic.
    ///
    /// auth_methods are the ways clients are supposed to be able to authenticate to your server.
    ///
    /// If you choose to use the UsernamePassword method, a non-`None` `username` and `password` must be supplied.
    ///
    /// If clients should omit one or both of them, pass the empty `String`.
    ///
    /// If username/password auth is not to be used, these fields should be `None` for the sake of clarity, but are ignored.
    pub fn init(
        bind_addr: net::SocketAddr,
        timeout: Option<time::Duration>,
        auth_methods: Vec<AuthMethod>,
        username: Option<String>,
        password: Option<String>,
    ) -> Result<SOCKSServer, io::Error> {
        let listener = net::TcpListener::bind(&bind_addr)?;
        let server = SOCKSServer {
            listener: listener,
            timeout: timeout,
            auth_methods: auth_methods,
            username: username,
            password: password,
        };
        return Ok(server);
    }
}

impl Iterator for SOCKSServer {
    type Item = Result<UnrequitedSOCKSConnection, SOCKSError>;
    fn next(&mut self) -> Option<Self::Item> {
        let stream: net::TcpStream;
        match self.listener.accept() {
            Ok(val) => {
                stream = val.0;
                stream.set_read_timeout(self.timeout).unwrap();
                stream.set_write_timeout(self.timeout).unwrap();
            }
            Err(e) => return Some(Err(SOCKSError::StreamIOError(e))),
        }
        match UnrequitedSOCKSConnection::init(
            stream,
            self.auth_methods.clone(),
            self.username.clone(),
            self.password.clone(),
        ) {
            Ok(val) => return Some(Ok(val)),
            Err(err) => return Some(Err(err)),
        }
    }
}
