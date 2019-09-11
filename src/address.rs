use std::net;

#[derive(PartialEq)]
pub(crate) enum AddressType {
    Unknown,
    V4,
    DomainName,
    V6,
}

impl AddressType {
    pub(crate) fn from_byte(b: u8) -> AddressType {
        match b {
            0x01 => return AddressType::V4,
            0x03 => return AddressType::DomainName,
            0x04 => return AddressType::V6,
            _ => return AddressType::Unknown,
        }
    }

    pub(crate) fn to_byte(&self) -> u8 {
        match self {
            AddressType::V4 => return 0x01,
            AddressType::DomainName => return 0x03,
            AddressType::V6 => return 0x04,
            AddressType::Unknown => panic!("Attempt to serialize unknown AddressType. This is a bug!"),
        }
    }

    pub(crate) fn from_socket_addr(s: net::SocketAddr) -> AddressType {
        if s.is_ipv4() {
            return AddressType::V4;
        } else if s.is_ipv6() {
            return AddressType::V6;
        } else {
            panic!("Unknown SocketAddr address type!");
        }
    }
}