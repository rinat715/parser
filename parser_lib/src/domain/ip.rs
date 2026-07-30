use std::convert::{From, Into};
use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use serde::ser::{Serialize, SerializeMap, Serializer};

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::domain::pythonize::tuple;

#[derive(Debug, PartialEq, Clone)]
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

impl From<IP> for IpAddr {
    fn from(val: IP) -> Self {
        val.0
    }
}

#[derive(Clone)]
pub struct IPAddress(IpNet);

impl IPAddress {
    pub fn new_assert(ip: IP, prefix_len: u8) -> Self {
        let ip = IpNet::new_assert(ip.into(), prefix_len);
        Self(ip)
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

impl<'a> IntoPy<PyObject> for IPAddress {
    fn into_py(self, py: Python) -> PyObject {

        let l = PyList::new(
            py,
            &[
                tuple(py, "Address", self.0.addr().to_string()),
                tuple(py, "NetworkID", self.0.network().to_string()),
                tuple(py, "Prefix", self.0.prefix_len()),
            ],
        );
        let dict = PyDict::from_sequence(py, l.into()).unwrap_or(PyDict::new(py));
        dict.into_py(py) // Py_INCREF
    }
}
