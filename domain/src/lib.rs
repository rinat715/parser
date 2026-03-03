use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};
use serde_derive::Serialize;

pub mod operators;
pub use operators::*;

pub mod ip;
pub use ip::IP;
pub mod nftables;
use macros::ToPyDict;

#[derive(Debug, PartialEq, Eq)]
pub struct ParseEnumError; // TODO нормальное название

pub fn is_empty<T>(values: &Vec<T>) -> bool {
    values.is_empty()
}

pub trait Builder {
    type Result;

    fn build(self) -> Self::Result;
}

#[derive(Clone, Serialize)]
pub enum Protocol<'a> {
    #[serde(rename(serialize = "Protocol", deserialize = "Protocol"))]
    String(StringOperator<'a>),
    #[serde(rename(serialize = "Protocol", deserialize = "Protocol"))]
    Number(IntOperator),
}

impl<'a> Protocol<'a> {
    pub fn ip() -> Self {
        Self::String(StringOperator::new(OperatorType::EQ, vec!["ip"]))
    }
}

impl<'a> IntoPy<PyObject> for Protocol<'a> {
    fn into_py(self, py: Python) -> PyObject {
        match self {
            Self::String(v) => v.into_py(py),
            Self::Number(v) => v.into_py(py),
        }
    }
}

#[derive(Serialize, Default, ToPyDict)]
#[serde(rename_all(serialize = "PascalCase", deserialize = "snake_case"))]
pub struct TCPUDPOptions<'a> {
    #[serde(skip_serializing_if = "is_empty")]
    pub source_ports: Vec<IntOperator>,
    #[serde(skip_serializing_if = "is_empty")]
    pub destination_ports: Vec<IntOperator>,
    #[serde(skip_serializing_if = "is_empty")]
    pub flags: Vec<StringOperator<'a>>,
}

impl<'a> TCPUDPOptions<'a> {
    pub fn new(
        source_ports: Vec<IntOperator>,
        destination_ports: Vec<IntOperator>,
        flags: Vec<StringOperator<'a>>,
    ) -> Self {
        Self {
            source_ports: source_ports,
            destination_ports: destination_ports,
            flags: flags,
        }
    }
}

#[derive(Serialize, ToPyDict)]
pub struct IPv4Options {
    fragments: Vec<IntOperator>,
    dscp: Vec<IntOperator>,
    precedence: Vec<IntOperator>,
    ip_protocol_options: Vec<IntOperator>,
    ttl: Vec<IntOperator>,
    packet_length: Vec<IntOperator>,
}

impl IPv4Options {
    pub fn new(
        fragments: Vec<IntOperator>,
        dscp: Vec<IntOperator>,
        precedence: Vec<IntOperator>,
        ip_protocol_options: Vec<IntOperator>,
        ttl: Vec<IntOperator>,
        packet_length: Vec<IntOperator>,
    ) -> Self {
        Self {
            fragments: fragments,
            dscp: dscp,
            precedence: precedence,
            ip_protocol_options: ip_protocol_options,
            ttl: ttl,
            packet_length: packet_length,
        }
    }
}

#[derive(Serialize, ToPyDict)]
pub struct ICMPOptions {
    code: Vec<IntOperator>,
    type_: Vec<IntOperator>,
}

impl ICMPOptions {
    pub fn new(code: Vec<IntOperator>, type_: Vec<IntOperator>) -> Self {
        Self {
            code: code,
            type_: type_,
        }
    }
}

#[derive(Serialize)]
pub struct ProtocolSetting<'a, T> {
    object_group: Option<StringOperator<'a>>,
    #[serde(flatten)]
    protocol: Protocol<'a>,
    #[serde(rename(serialize = "TCPUDPOptions", deserialize = "TCPUDPOptions"))]
    tcp_udp_options: Option<TCPUDPOptions<'a>>, 
    #[serde(rename(serialize = "IPv4Options", deserialize = "IPv4Options"))]
    ip_options: Option<T>,
    icmp_options: Option<ICMPOptions>,
}

impl<'a, T> ProtocolSetting<'a, T> {
    pub fn new(
        object_group: Option<StringOperator<'a>>,
        protocol: Protocol<'a>,
        tcp_udp_options: Option<TCPUDPOptions<'a>>,
        ip_options: Option<T>,
        icmp_options: Option<ICMPOptions>,
    ) -> Self {
        Self {
            object_group,
            protocol,
            tcp_udp_options,
            ip_options,
            icmp_options,
        }
    }
}

impl<'a, T> IntoPy<PyObject> for ProtocolSetting<'a, T>
where
    T: IntoPy<PyObject>,
{
    fn into_py(self, py: Python) -> PyObject {
        let dict = PyDict::new(py);
        dict.set_item::<PyObject, PyObject>("protocol".into_py(py), self.protocol.into_py(py))
            .expect("Failed to set_item on dict");
        dict.set_item::<PyObject, PyObject>(
            "tcp_udp_options".into_py(py),
            self.tcp_udp_options.into_py(py),
        )
        .expect("Failed to set_item on dict");
        dict.set_item::<PyObject, PyObject>("ip_options".into_py(py), self.ip_options.into_py(py))
            .expect("Failed to set_item on dict");
        dict.set_item::<PyObject, PyObject>(
            "icmp_options".into_py(py),
            self.icmp_options.into_py(py),
        )
        .expect("Failed to set_item on dict");
        dict.into()
    }
}

#[derive(Clone)]
pub enum StringOrU16<'a> {
    String(&'a str),
    Number(u16),
}

impl<'a> Protocol<'a> {
    // TODO ??????
    pub fn new(operator_type: OperatorType, value: StringOrU16<'a>) -> Self {
        match value {
            StringOrU16::Number(v) => Self::Number(IntOperator::new(operator_type, vec![v])),
            StringOrU16::String(v) => Self::String(StringOperator::new(operator_type, vec![v])),
        }
    }
}

#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all(serialize = "lowercase", deserialize = "UPPERCASE"))]
pub enum NormalizedAction {
    PERMIT,
    DENY,
    JUMP,
    PASS,
    RETURN,
}

impl<'a> IntoPy<PyObject> for NormalizedAction {
    fn into_py(self, py: Python) -> PyObject {
        match self {
            Self::PERMIT => PyString::new(py, "PERMIT").into_py(py),
            Self::DENY => PyString::new(py, "DENY").into_py(py),
            Self::JUMP => PyString::new(py, "JUMP").into_py(py),
            Self::PASS => PyString::new(py, "PASS").into_py(py),
            Self::RETURN => PyString::new(py, "RETURN").into_py(py),
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Default)]
pub struct ActionSetting<'a, T> {
    action: T,
    option: &'a str,
}

impl<'a, T> ActionSetting<'a, T>
where
    T: TryInto<NormalizedAction, Error = ParseEnumError> + Clone + Default,
{
    pub fn new(action: T, option: &'a str) -> Self
    where
        T: TryInto<NormalizedAction>,
    {
        Self {
            action: action,
            option: option,
        }
    }

    pub fn is_type(&self, kind: T) -> bool
    where
        T: std::cmp::PartialEq,
    {
        self.action == kind
    }

    pub fn normalized_action(&self) -> Result<NormalizedAction, ParseEnumError> {
        self.action.clone().try_into()
    }

    pub fn action(&mut self, action: T) -> &mut Self {
        self.action = action;
        self
    }

    pub fn option(&mut self, option: &'a str) -> &mut Self {
        self.option = option;
        self
    }
}

impl<'a, T> IntoPy<PyObject> for ActionSetting<'a, T>
where
    T: IntoPy<PyObject>,
{
    fn into_py(self, py: Python) -> PyObject {
        let dict = PyDict::new(py);
        dict.set_item::<PyObject, PyObject>("operator".into_py(py), self.action.into_py(py))
            .expect("Failed to set_item on dict");
        dict.set_item::<PyObject, PyObject>("values".into_py(py), self.option.into_py(py))
            .expect("Failed to set_item on dict");
        dict.into_py(py)
    }
}

#[derive(Debug, PartialEq, Serialize, Default)]
pub struct ACLRule<'a, T> {
    pub action_modifiers: Option<Vec<ActionSetting<'a, T>>>,
    pub action: Option<Vec<ActionSetting<'a, T>>>,
    pub normalized_action: Option<NormalizedAction>,
    pub line_number: Option<u16>,
}
