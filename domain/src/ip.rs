use ipnet::{IpNet, PrefixLenError};
use std::convert::{From, Into};
use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr};

use serde::ser::{Serialize, SerializeMap, Serializer};

#[derive(Debug, PartialEq)]
pub struct IP(IpAddr);

impl Serialize for IP {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;
        match self.0 {
            IpAddr::V4(ip) => {
                map.serialize_entry("Address", &ip)?;
                map.serialize_entry("Version", &4)?;
            }
            IpAddr::V6(ip) => {
                map.serialize_entry("Address", &ip)?;
                map.serialize_entry("Version", &6)?;
            }
        }
        map.end()
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
        let ip: Ipv6Addr = arg.parse()?;
        Ok(Self(ip.into()))
    }

    pub fn parse_ip4(arg: &str) -> Result<Self, AddrParseError> {
        let ip: Ipv4Addr = arg.parse()?;
        Ok(Self(ip.into()))
    }
}

impl From<IpAddr> for IP {
    fn from(item: IpAddr) -> Self {
        IP(item)
    }
}

impl Into<IpAddr> for IP {
    fn into(self) -> IpAddr {
        self.0
    }
}

pub struct IPAddress_ {
    address: IpNet,
    wildcard: Option<IpAddr>,
}

impl IPAddress_ {
    fn new(ip: IpNet) -> Self {
        Self {
            address: ip,
            wildcard: None,
        }
    }
}

pub enum IPAddress {
    Network(IPAddress_),
    Address(IPAddress_),
}

impl IPAddress {
    pub fn to_ip_address(ip: IP, prefix_len: u8) -> Result<Self, PrefixLenError> {
        Ok(Self::Address(IPAddress_::new(IpNet::new(
            ip.into(),
            prefix_len,
        )?)))
    }
}

impl Serialize for IPAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(3))?; // TODO wildcard

        match self {
            IPAddress::Address(ip) => {
                let addr: IP = ip.address.addr().into();
                let network: IP = ip.address.network().into();
                let prefix = ip.address.prefix_len();

                map.serialize_entry("Address", &addr)?;
                map.serialize_entry("NetworkID", &network)?;
                map.serialize_entry("Prefix", &prefix)?;
            }
            _ => unimplemented!(),
        }
        map.end()
    }
}
