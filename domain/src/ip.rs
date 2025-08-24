use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr};

use serde::ser::{Serialize, SerializeStruct, Serializer};

#[derive(Debug, PartialEq)]
pub struct IP(IpAddr);

impl Serialize for IP {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("IP", 2)?;
        match self.0 {
            IpAddr::V4(ip) => {
                state.serialize_field("Address", &ip)?;
                state.serialize_field("Version", &4)?;
            }
            IpAddr::V6(ip) => {
                state.serialize_field("Address", &ip)?;
                state.serialize_field("Version", &6)?;
            }
        }
        state.end()
    }
}

impl IP {
    pub fn new_ip4(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
    }

    pub fn new_ip6(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> Self {
        Self(IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h)))
    }

    pub fn parse_ip6(arg: &str) -> Result<Self, AddrParseError> {
        let ip6: Ipv6Addr = arg.parse()?;
        Ok(Self(IpAddr::V6(ip6)))
    }
}
