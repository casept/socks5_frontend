use std::net;
use std::fmt;

#[derive(PartialEq, Clone)]
pub enum Address {
    V4(net::Ipv4Addr),
    DomainName(String),
    V6(net::Ipv6Addr),
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::V4(addr) => write!(f, "{}", addr),
            Address::V6(addr) => write!(f, "{}", addr),
            Address::DomainName(addr) => write!(f, "{}", addr),
        }
    }
}
