use crate::address::AddressType;

use byteorder::{NetworkEndian, WriteBytesExt};
use std::io::Write;
use std::net;

enum ReplyType {
    Succeeded,
    GeneralSocksServerFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    DestinationUnreachable,
    ConnectionRefused,
    TTLExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
}

impl ReplyType {
    fn to_byte(&self) -> u8 {
        match self {
            ReplyType::Succeeded => return 0x00,
            ReplyType::GeneralSocksServerFailure => return 0x01,
            ReplyType::ConnectionNotAllowed => return 0x02,
            ReplyType::NetworkUnreachable => return 0x03,
            ReplyType::DestinationUnreachable => return 0x04,
            ReplyType::ConnectionRefused => return 0x05,
            ReplyType::TTLExpired => return 0x06,
            ReplyType::CommandNotSupported => return 0x07,
            ReplyType::AddressTypeNotSupported => return 0x08,
        }
    }
}
pub(crate) struct SOCKSReply {
    rep: Option<ReplyType>,
    atyp: AddressType,
    bnd_addr: net::IpAddr,
    bnd_port: u16, // Remember to convert to BE before sending!
}

impl SOCKSReply {
    pub(crate) fn new(dest_conn_source_addr: net::SocketAddr) -> SOCKSReply {
        return SOCKSReply {
            rep: None,
            atyp: AddressType::from_socket_addr(dest_conn_source_addr),
            bnd_addr: dest_conn_source_addr.ip(),
            bnd_port: dest_conn_source_addr.port(),
        };
    }

    fn send(&mut self, s: &mut net::TcpStream) {
        // TODO: Error handling!
        let ver_buf: [u8; 1] = [5];
        s.write(&ver_buf).unwrap();
        let rep_buf: [u8; 1] = [self.rep.as_ref().unwrap().to_byte()];
        s.write(&rep_buf).unwrap();
        let rsv_buf: [u8; 1] = [0];
        s.write(&rsv_buf).unwrap();
        let atyp_buf: [u8; 1] = [self.atyp.to_byte()];
        s.write(&atyp_buf).unwrap();
        let bnd_addr_buf = match self.bnd_addr {
            net::IpAddr::V4(ip) => ip.octets().to_vec(),
            net::IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        s.write(&bnd_addr_buf).unwrap();
        // Make sure the port has correct endianess
        let mut bnd_port_buf: Vec<u8> = Vec::new();
        bnd_port_buf
            .write_u16::<NetworkEndian>(self.bnd_port)
            .unwrap();
        s.write(&bnd_port_buf).unwrap();
    }

    pub(crate) fn report_success(&mut self, s: &mut net::TcpStream) {
        self.rep = Some(ReplyType::Succeeded);
        self.send(s);
    }

    pub(crate) fn report_connection_not_allowed(&mut self, s: &mut net::TcpStream) {
        self.rep = Some(ReplyType::ConnectionNotAllowed);
        self.send(s);
        // The spec expects us to close the connection after a failure
        s.shutdown(net::Shutdown::Both).unwrap(); // TODO: Does this actually flush the error response to the client first?
    }
    pub(crate) fn report_network_unreachable(&mut self, s: &mut net::TcpStream) {
        self.rep = Some(ReplyType::NetworkUnreachable);
        self.send(s);
        // The spec expects us to close the connection after a failure
        s.shutdown(net::Shutdown::Both).unwrap();
    }
    pub(crate) fn report_destination_unreachable(&mut self, s: &mut net::TcpStream) {
        self.rep = Some(ReplyType::DestinationUnreachable);
        self.send(s);
        // The spec expects us to close the connection after a failure
        s.shutdown(net::Shutdown::Both).unwrap();
    }
    pub(crate) fn report_general_server_error(&mut self, s: &mut net::TcpStream) {
        self.rep = Some(ReplyType::GeneralSocksServerFailure);
        self.send(s);
        // The spec expects us to close the connection after a failure
        s.shutdown(net::Shutdown::Both).unwrap();
    }

    pub(crate) fn report_command_not_supported(&mut self, s: &mut net::TcpStream) {
        self.rep = Some(ReplyType::CommandNotSupported);
        self.send(s);
        // The spec expects us to close the connection after a failure
        s.shutdown(net::Shutdown::Both).unwrap();
    }

    pub(crate) fn report_address_type_not_supported(&mut self, s: &mut net::TcpStream) {
        self.rep = Some(ReplyType::AddressTypeNotSupported);
        self.send(s);
        // The spec expects us to close the connection after a failure
        s.shutdown(net::Shutdown::Both).unwrap();
    }

    pub(crate) fn report_connection_refused(&mut self, s: &mut net::TcpStream) {
        self.rep = Some(ReplyType::ConnectionRefused);
        self.send(s);
        // The spec expects us to close the connection after a failure
        s.shutdown(net::Shutdown::Both).unwrap();
    }
    pub(crate) fn report_ttl_expired(&mut self, s: &mut net::TcpStream) {
        self.rep = Some(ReplyType::TTLExpired);
        self.send(s);
        // The spec expects us to close the connection after a failure
        s.shutdown(net::Shutdown::Both).unwrap();
    }
}
