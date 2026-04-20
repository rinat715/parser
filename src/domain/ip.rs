use std::convert::{From, Into};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{AddrParseError, IpNet, PrefixLenError};
use serde::ser::{Serialize, SerializeMap, Serializer};

#[derive(Debug, PartialEq)]
pub struct IP(IpAddr);

impl IP {
    pub fn new_ip4(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
    }

    pub fn new_ip6(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> Self {
        Self(IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h)))
    }

    pub fn parse_ip6(arg: &str) -> Result<Self, std::net::AddrParseError> {
        let ip: Ipv6Addr = arg.parse()?;
        Ok(Self(ip.into()))
    }

    pub fn parse_ip4(arg: &str) -> Result<Self, std::net::AddrParseError> {
        let ip: Ipv4Addr = arg.parse()?;
        Ok(Self(ip.into()))
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

    pub fn new_ip_address(ip: IpAddr, prefix_len: IpAddr) -> Result<Self, PrefixLenError> {
        let ip = IpNet::with_netmask(ip, prefix_len)?;
        Ok(Self(ip))
    }

    pub fn new(ip: IpAddr, prefix_len: u8) -> Result<Self, PrefixLenError> {
        let ip = IpNet::new(ip, prefix_len)?;
         Ok(Self(ip))
    }

    pub fn to_ip_address(s: &str) -> Result<Self, AddrParseError> {
        let ip = s.parse()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_ip_address() {
        let res = IPAddress::to_ip_address("10.1.1.0/24").unwrap();
        assert_eq!(res.0.addr().to_string(), "10.1.1.0");

        let res = IPAddress::to_ip_address("10.10.10.10/28").unwrap();
        assert_eq!(res.0.addr().to_string(), "10.10.10.10");
        assert_eq!(res.0.network().to_string(), "10.10.10.0");

        let res = IPAddress::to_ip_address("192.168.0.1/32").unwrap();
        assert_eq!(res.0.addr().to_string(), "192.168.0.1");
        assert_eq!(res.0.network().to_string(), "192.168.0.1")
    }

    #[test]
    fn test_to_ip_address2() {
        let res = IPAddress::to_ip_address("10.10.10.0/28").unwrap();
        assert_eq!(res.0.addr().to_string(), "10.10.10.0");
        assert_eq!(res.0.network().to_string(), "10.10.10.0")
    }

    #[test]
    fn test_serialize() {
        let res = IPAddress::to_ip_address("10.1.1.0/24").unwrap();
        assert_eq!(
            "Prefix = 24

[Address]
Address = \"10.1.1.0\"
Version = 4

[NetworkID]
Address = \"10.1.1.0\"
Version = 4
",
            toml::to_string(&res).unwrap()
        )
    }
}
