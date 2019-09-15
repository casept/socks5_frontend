use crate::address::Address;
use crate::command::Command;
use crate::reply::SOCKSReply;
use crate::socks_error::SOCKSError;

use std::convert::TryInto;
use std::io::Read;
use std::net;

use byteorder::{NetworkEndian, ReadBytesExt};


const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

pub(crate) struct SOCKSRequest {
    stream: net::TcpStream,
    cmd: Command,
    atyp: u8,
    dst_addr: Address,
    dst_port: u16, // Remember to convert from BE!
}

impl SOCKSRequest {
    fn new(stream: net::TcpStream) -> SOCKSRequest {
        return SOCKSRequest {
            stream: stream,
            cmd: Command::Unknown,
            atyp: 0x00,
            dst_addr: Address::DomainName("".to_string()),
            dst_port: 0x00,
        };
    }

    // Keep transitioning between states until the protocol has been negotiated and return the TcpStream,
    // or error if negotiating with the client fails.
    pub(crate) fn from_stream(stream: &mut net::TcpStream) -> Result<SOCKSRequest, SOCKSError> {
        let cloned_stream = stream.try_clone().unwrap(); // Work around ownership issues

        let mut req = SOCKSRequest::new(cloned_stream);

        // Read the protocol version
        let mut ver_buf: [u8; 1] = [0x00];
        stream.read_exact(&mut ver_buf).unwrap();
        if ver_buf[0] != 5 {
            // Return an error to the client
            let mut reply = SOCKSReply::new(stream.local_addr().unwrap());
            reply.report_general_server_error(&mut req.stream);
            return Err(SOCKSError::ProtoolVersionError(
                req.stream.peer_addr().unwrap(),
                ver_buf[0],
            ));
        }

        // Read the type of command requested
        let mut cmd_buf: [u8; 1] = [0x00];
        stream.read_exact(&mut cmd_buf).unwrap();
        req.cmd = Command::from_byte(cmd_buf[0]);
        if req.cmd == Command::Unknown {
            let mut reply = SOCKSReply::new(stream.local_addr().unwrap());
            reply.report_command_not_supported(stream);
            return Err(SOCKSError::UnknownRequestCommandError(
                stream.peer_addr().unwrap(),
                cmd_buf[0],
            ));
        }

        // Read the reserved byte (which should always be 0)
        let mut rsv_buf: [u8; 1] = [0];
        stream.read_exact(&mut rsv_buf).unwrap();
        if rsv_buf[0] != 0 {
            let mut reply = SOCKSReply::new(stream.local_addr().unwrap());
            reply.report_general_server_error(stream);
            return Err(SOCKSError::UnknownReservedByteError(
                stream.peer_addr().unwrap(),
                rsv_buf[0],
            ));
        }
        // Read the type of address to connect to
        let mut atyp_buf: [u8; 1] = [0x00];
        stream.read_exact(&mut atyp_buf).unwrap();
        req.atyp = atyp_buf[0];

        // TODO: Error handling
        // Different types of address require specific handling
        match req.atyp {
            ATYP_V4 => {
                // Read the address that we'll proxy data to
                let mut buf: [u8; 4] = [0x00; 4];
                stream.read_exact(&mut buf).unwrap();
                // Convert these octets to IPAddr
                req.dst_addr = Address::V4(net::Ipv4Addr::from(buf));
            },
            ATYP_V6 => {
                // Read the address that we'll proxy data to
                let mut buf: [u8; 16] = [0x00; 16];
                stream.read_exact(&mut buf).unwrap();
                // Convert these octets to IPAddr
                req.dst_addr = Address::V6(net::Ipv6Addr::from(buf));
            },
            ATYP_DOMAIN => {
                // The first byte contains the length of the domain name
                let mut name_len_buf: [u8; 1] = [0x00];
                stream.read_exact(&mut name_len_buf).unwrap();
                let addr_buf_len = name_len_buf[0];
                let mut buf: Vec<u8> = vec![0; addr_buf_len.try_into().unwrap()];
                stream.read_exact(&mut buf).unwrap();
                req.dst_addr = Address::DomainName(String::from_utf8(buf).unwrap())
            },
            _ => {
                // Unknown address type
                let mut reply = SOCKSReply::new(stream.local_addr().unwrap());
                reply.report_address_type_not_supported(stream);
                return Err(SOCKSError::UnknownAddressTypeError(
                    stream.peer_addr().unwrap(),
                    req.atyp,
                ));
            },
        }

        // Read the port that we'll proxy data to (in host byte order)
        req.dst_port = stream.read_u16::<NetworkEndian>().unwrap();
        return Ok(req);
    }

    pub(crate) fn get_dst_addr(&self) -> Address {
        return self.dst_addr.clone();
    }
    pub(crate) fn get_dst_port(&self) -> u16 {
        return self.dst_port;
    }
}
