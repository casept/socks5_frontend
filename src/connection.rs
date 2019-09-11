use crate::reply::SOCKSReply;
use crate::request::SOCKSRequest;
use crate::socks_error::SOCKSError;

use std::io::Read;
use std::io::Write;
use std::net;

const NO_AUTH: u8 = 0x00;
const NO_SUPPORTED_AUTH_METHODS: u8 = 0xFF;

/*
If the connection
   request succeeds, the client enters a negotiation for the
   authentication method to be used, authenticates with the chosen
   method, then sends a relay request.  The SOCKS server evaluates the
   request, and either establishes the appropriate connection or denies
   it.
*/

pub struct SOCKSConnection {
    stream: net::TcpStream,
    client_auth_methods: Vec<u8>,
    dst_addr: String,
    dst_port: u16,
}

impl SOCKSConnection {
    /// Negotiates a connection with the client and returns the TcpStream the client is connected to.
    pub(crate) fn init(stream: net::TcpStream) -> Result<SOCKSConnection, SOCKSError> {
        let mut conn = SOCKSConnection {
            stream: stream,
            client_auth_methods: Vec::new(),
            dst_addr: String::new(),
            dst_port: 0,
        };

        // FIXME: Handle r/w timeouts everywhere by returning appropriate SOCKSError
        // Ensure that the client speaks SOCKS5
        let mut version_buf: [u8; 1] = [0];
        conn.stream.read_exact(&mut version_buf).unwrap();
        if version_buf[0] != 5 {
            let mut reply = SOCKSReply::new(conn.stream.local_addr().unwrap());
            reply.report_general_server_error(&mut conn.stream);
            return Err(SOCKSError::ProtoolVersionError(
                conn.stream.peer_addr().unwrap(),
                version_buf[0],
            ));
        }

        // Read how many authentication methods the client supports
        let mut nmethods_buf: [u8; 1] = [0];
        conn.stream.read_exact(&mut nmethods_buf).unwrap();
        if nmethods_buf[0] == 0 {
            let mut reply = SOCKSReply::new(conn.stream.local_addr().unwrap());
            reply.report_general_server_error(&mut conn.stream);
            return Err(SOCKSError::NoAuthMethodsError(
                conn.stream.peer_addr().unwrap(),
            ));
            // TODO: Close connections after error (not just here)
        }

        // Read the authentication methods supported by the client and check for overlap with ours
        let mut methods_buf = vec![0; nmethods_buf[0].into()];
        conn.stream.read_exact(&mut methods_buf).unwrap();
        // TODO: Support username/pw and GSSAPI auth
        if !methods_buf.contains(&NO_AUTH) {
            // Tell the client there's no overlap in auth methods
            let proto_ver: [u8; 1] = [5];
            conn.stream.write(&proto_ver).unwrap();
            let no_compat_methods: [u8; 1] = [NO_SUPPORTED_AUTH_METHODS];
            conn.stream.write(&no_compat_methods).unwrap();
            // Close the connection, as mandated by the spec
            conn.stream.shutdown(net::Shutdown::Both).unwrap();
            return Err(SOCKSError::UnsupportedAuthMethodError(
                conn.stream.peer_addr().unwrap(),
                conn.client_auth_methods.to_vec(),
                vec![NO_AUTH],
            ));
        } else {
            let proto_ver: [u8; 1] = [5];
            conn.stream.write(&proto_ver).unwrap();
            // Otherwise, tell the client to use no auth (0x00), because it's the only one we support right now
            let no_auth: [u8; 1] = [NO_AUTH];
            conn.stream.write(&no_auth).unwrap();
        }

        // Read the client's request, which contains information such as the destination server.
        let mut cloned_stream = conn.stream.try_clone().unwrap();
        let req = SOCKSRequest::from_stream(&mut cloned_stream)?;
        conn.dst_addr = req.get_dst_addr();
        conn.dst_port = req.get_dst_port();

        return Ok(conn);
    }

    pub fn get_stream(self) -> net::TcpStream {
        return self.stream;
    }
}

/// Because a SOCKS client always expects one (and only one) SOCKS server response before data gets relayed,
/// it's not safe to allow consumers access to the underlying stream before they have reported to the client
/// whether the request can be handled.
/// Therefore, this object only exposes information to the consumer that is relevant to making that decision.
/// Once the consumer has called any of the `report` methods, it's safe to start relaying data and a `SOCKSConnection` that
/// can do this is returned.
pub struct UnrequitedSOCKSConnection {
    underlying_connection: SOCKSConnection,
}

impl UnrequitedSOCKSConnection {
    pub(crate) fn init(stream: net::TcpStream) -> Result<UnrequitedSOCKSConnection, SOCKSError> {
        let socks_conn = SOCKSConnection::init(stream)?;
        return Ok(UnrequitedSOCKSConnection {
            underlying_connection: socks_conn,
        });
    }

    pub fn report_success(mut self) -> SOCKSConnection {
        let mut reply = SOCKSReply::new(self.underlying_connection.stream.local_addr().unwrap());
        reply.report_success(&mut self.underlying_connection.stream);
        return self.underlying_connection;
    }
    pub fn report_connection_not_allowed(mut self) {
        let mut reply = SOCKSReply::new(self.underlying_connection.stream.local_addr().unwrap());
        reply.report_connection_not_allowed(&mut self.underlying_connection.stream);
    }

    pub fn report_destination_unreachable(mut self) {
        let mut reply = SOCKSReply::new(self.underlying_connection.stream.local_addr().unwrap());
        reply.report_destination_unreachable(&mut self.underlying_connection.stream);
    }
    pub fn report_network_unreachable(mut self) {
        let mut reply = SOCKSReply::new(self.underlying_connection.stream.local_addr().unwrap());
        reply.report_network_unreachable(&mut self.underlying_connection.stream);
    }

    pub fn report_connection_refused(mut self) {
        let mut reply = SOCKSReply::new(self.underlying_connection.stream.local_addr().unwrap());
        reply.report_connection_refused(&mut self.underlying_connection.stream);
    }
    pub fn report_ttl_expired(mut self) {
        let mut reply = SOCKSReply::new(self.underlying_connection.stream.local_addr().unwrap());
        reply.report_ttl_expired(&mut self.underlying_connection.stream);
    }

    pub fn get_client_address(&self) -> net::SocketAddr {
        return self.underlying_connection.stream.peer_addr().unwrap();
    }

    pub fn get_destination_address(&self) -> (String, u16) {
        return (
            self.underlying_connection.dst_addr.clone(),
            self.underlying_connection.dst_port,
        );
    }
}
