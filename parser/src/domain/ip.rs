use std::convert::{From, Into};
use std::net::{IpAddr, Ipv4Addr};

use ipnet::{IpNet, PrefixLenError};
use serde::ser::{Serialize, SerializeMap, Serializer};

#[derive(Debug, PartialEq)]
pub struct IP(IpAddr);

impl IP {
    pub fn new_ip4(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
    }
}

impl Serialize for IP {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;
        match self.0 {
            IpAddr::V4(ip) => {
                map.serialize_entry("Address", &ip.to_string())?;
                map.serialize_entry("Version", &4)?;
            }
            IpAddr::V6(ip) => {
                map.serialize_entry("Address", &ip.to_string())?;
                map.serialize_entry("Version", &6)?;
            }
        }
        map.end()
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


#[derive(Clone)]
pub struct IPAddress(IpNet);

impl IPAddress {
    pub fn new_assert(ip: IP, prefix_len: u8) -> Self {
        let ip = IpNet::new_assert(ip.into(), prefix_len);
        Self(ip)
    }

    pub fn new(ip: IpAddr, prefix_len: u8) -> Result<Self, PrefixLenError> {
        let ip = IpNet::new(ip, prefix_len)?;
         Ok(Self(ip))
    }
}

impl Serialize for IPAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(3))?; // TODO wildcard

        let addr: IP = IP(self.0.addr());
        let network: IP = IP(self.0.network());
        let prefix = self.0.prefix_len();

        map.serialize_entry("Address", &addr)?;
        map.serialize_entry("NetworkID", &network)?;
        map.serialize_entry("Prefix", &prefix)?;

        map.end()
    }
}