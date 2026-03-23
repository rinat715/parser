use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};
use serde_derive::Serialize;

pub mod operators;
pub use operators::*;

pub mod ip;
pub use ip::*;

use macros::{is_not_null, ToPyDict};
pub mod nftables;

#[derive(Debug, PartialEq, Eq)]
pub struct ParseEnumError; // TODO нормальное название

pub fn is_empty<T>(values: &Vec<T>) -> bool {
    values.is_empty()
}

pub trait Builder {
    type Result;

    fn build(self) -> Self::Result;
}

pub trait Mapping<T> {
    fn mapping(&mut self, target: T);
}

#[derive(Clone)]
pub enum StringOrU16<'a> {
    String(&'a str),
    Number(u16),
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

impl<'a> Protocol<'a> {
    // TODO ??????
    pub fn new(operator_type: OperatorType, value: StringOrU16<'a>) -> Self {
        match value {
            StringOrU16::Number(v) => Self::Number(IntOperator::new(operator_type, vec![v])),
            StringOrU16::String(v) => Self::String(StringOperator::new(operator_type, vec![v])),
        }
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
    source_ports: Vec<IntOperator>,
    #[serde(skip_serializing_if = "is_empty")]
    destination_ports: Vec<IntOperator>,
    #[serde(skip_serializing_if = "is_empty")]
    flags: Vec<StringOperator<'a>>,
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

pub static TCP_FLAGS_ALL: [&str; 6] = ["SYN", "ACK", "FIN", "RST", "URG", "PSH"];

pub fn tcp_flags<'a>(
    operator: OperatorType,
    value: (Vec<&'a str>, Vec<&'a str>),
) -> (StringOperator<'a>, StringOperator<'a>) {
    let values: Vec<&str>;

    if operator == OperatorType::EQ {
        values = value
            .0
            .into_iter()
            .filter(|x| !value.1.contains(x))
            .collect()
    } else {
        values = TCP_FLAGS_ALL
            .into_iter()
            .filter(|x| !value.0.contains(x))
            .collect()
    }

    let first = StringOperator::new(OperatorType::NEQ, values);
    let second: StringOperator<'_> = StringOperator::new(OperatorType::EQ, value.1);

    (first, second)
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

#[derive(Serialize)]
pub enum IPOptions {
    #[serde(rename(serialize = "IPv4Options", deserialize = "IPv4Options"))]
    IPv4(IPv4Options),
}

impl IPOptions {
    pub fn new_ip4(
        fragments: Vec<IntOperator>,
        dscp: Vec<IntOperator>,
        precedence: Vec<IntOperator>,
        ip_protocol_options: Vec<IntOperator>,
        ttl: Vec<IntOperator>,
        packet_length: Vec<IntOperator>,
    ) -> Self {
        Self::IPv4(IPv4Options::new(
            fragments,
            dscp,
            precedence,
            ip_protocol_options,
            ttl,
            packet_length,
        ))
    }
}

impl IntoPy<PyObject> for IPOptions {
    fn into_py(self, py: Python) -> PyObject {
        match self {
            Self::IPv4(v) => v.into_py(py),
        }
    }
}

#[derive(Serialize, ToPyDict)]
pub struct ICMPOptions {
    code: Vec<IntOperator>,
    type_: Vec<IntOperator>,
}

//IPv4Options = IPv4Options()
//IPv6Options = IPv6Options()

#[derive(Serialize)]
pub struct ProtocolSetting<'a> {
    object_group: Option<StringOperator<'a>>,
    #[serde(flatten)]
    protocol: Option<Protocol<'a>>,
    #[serde(rename(serialize = "TCPUDPOptions", deserialize = "TCPUDPOptions"))]
    tcp_udp_options: Option<TCPUDPOptions<'a>>,
    #[serde(flatten)]
    ip_options: Option<IPOptions>,
    icmp_options: Option<ICMPOptions>,
}

impl<'a> ProtocolSetting<'a> {
    pub fn new(
        object_group: Option<StringOperator<'a>>,
        protocol: Option<Protocol<'a>>,
        tcp_udp_options: Option<TCPUDPOptions<'a>>,
        ip_options: Option<IPOptions>,
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

    pub fn builder() -> ProtocolSettingBuilder<'a> {
        ProtocolSettingBuilder::new()
    }
}

impl<'a> IntoPy<PyObject> for ProtocolSetting<'a> {
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

pub struct ProtocolSettingBuilder<'a> {
    //protocol
    object_group: Option<StringOperator<'a>>,
    protocol: Option<Protocol<'a>>,
    // tcp_udp_options
    source_ports: Vec<IntOperator>,
    destination_ports: Vec<IntOperator>,
    flags: Vec<StringOperator<'a>>,
    // IPv4Options
    fragments: Vec<IntOperator>,
    dscp: Vec<IntOperator>,
    precedence: Vec<IntOperator>,
    ip_protocol_options: Vec<IntOperator>,
    ttl: Vec<IntOperator>,
    packet_length: Vec<IntOperator>,
    // ICMPOptions
    code: Vec<IntOperator>,
    type_: Vec<IntOperator>,
}

impl<'a> ProtocolSettingBuilder<'a> {
    pub fn new() -> Self {
        Self {
            object_group: None,
            protocol: None,
            source_ports: vec![],
            destination_ports: vec![],
            flags: vec![],
            fragments: vec![],
            dscp: vec![],
            precedence: vec![],
            ip_protocol_options: vec![],
            ttl: vec![],
            packet_length: vec![],
            code: vec![],
            type_: vec![],
        }
    }

    #[is_not_null(all)]
    fn tcp_udp_options(
        sports: Vec<IntOperator>,
        dports: Vec<IntOperator>,
        flags: Vec<StringOperator<'a>>,
    ) -> Option<TCPUDPOptions<'a>> {
        Some(TCPUDPOptions::new(sports, dports, flags))
    }

    #[is_not_null(all)]
    fn ip_v_4options(
        fragments: Vec<IntOperator>,
        dscp: Vec<IntOperator>,
        precedence: Vec<IntOperator>,
        ip_protocol_options: Vec<IntOperator>,
        ttl: Vec<IntOperator>,
        packet_length: Vec<IntOperator>,
    ) -> Option<IPOptions> {
        Some(IPOptions::new_ip4(
            fragments,
            dscp,
            precedence,
            ip_protocol_options,
            ttl,
            packet_length,
        ))
    }

    pub fn set_protocol(&mut self, value: Option<Protocol<'a>>) -> &mut Self {
        value.is_some().then(|| self.protocol = value);
        self
    }

    pub fn extend_source_ports(&mut self, values: Vec<IntOperator>) -> &mut Self {
        self.source_ports.extend(values);
        self
    }

    pub fn extend_destination_ports(&mut self, values: Vec<IntOperator>) -> &mut Self {
        self.destination_ports.extend(values);
        self
    }

    pub fn set_flags(
        &mut self,
        pair: Option<(StringOperator<'a>, StringOperator<'a>)>,
    ) -> &mut Self {
        pair.map(|(f, s)| {
            self.flags.push(f);
            self.flags.push(s);
        });
        self
    }

    pub fn add_ttl(&mut self, value: Option<IntOperator>) -> &mut Self {
        value.map(|v| self.ttl.push(v));
        self
    }

    pub fn add_fragment(&mut self, value: Option<IntOperator>) -> &mut Self {
        value.map(|v| self.fragments.push(v));
        self
    }

    pub fn add_dscp(&mut self, value: Option<IntOperator>) -> &mut Self {
        value.map(|v| self.dscp.push(v));
        self
    }

    pub fn add_packet_length(&mut self, value: Option<IntOperator>) -> &mut Self {
        value.map(|v| self.packet_length.push(v));
        self
    }

    pub fn extend_ip_protocol_options(&mut self, values: Vec<IntOperator>) -> &mut Self {
        self.ip_protocol_options.extend(values);
        self
    }

    pub fn build(mut self, default: ProtocolSetting<'a>) -> ProtocolSetting<'a> {
        default.tcp_udp_options.map(|v| {
            self.source_ports
                .is_empty()
                .then(|| self.source_ports = v.source_ports);
            self.destination_ports
                .is_empty()
                .then(|| self.destination_ports = v.destination_ports);
            self.flags.is_empty().then(|| self.flags = v.flags)
        });

        default.ip_options.map(|ip_options| match ip_options {
            IPOptions::IPv4(v) => {
                self.fragments
                    .is_empty()
                    .then(|| self.fragments = v.fragments);
                self.dscp.is_empty().then(|| self.dscp = v.dscp);
                self.precedence
                    .is_empty()
                    .then(|| self.precedence = v.precedence);
                self.ip_protocol_options
                    .is_empty()
                    .then(|| self.ip_protocol_options = v.ip_protocol_options);
                self.ttl.is_empty().then(|| self.ttl = v.ttl);
            }
        });

        ProtocolSetting::new(
            self.object_group.or(default.object_group),
            self.protocol.or(default.protocol),
            Self::tcp_udp_options(self.source_ports, self.destination_ports, self.flags),
            Self::ip_v_4options(
                self.fragments,
                self.dscp,
                self.precedence,
                self.ip_protocol_options,
                self.ttl,
                self.packet_length,
            ),
            None,
        )
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

#[derive(Debug, PartialEq, Serialize)]
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

    pub fn normalized_action(&self) -> Result<NormalizedAction, ParseEnumError> {
        self.action.clone().try_into()
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

#[derive(Serialize)]
#[serde(rename_all(serialize = "PascalCase", deserialize = "snake_case"))]
pub struct ACLRule<'a, T> {
    action_modifiers: Vec<ActionSetting<'a, T>>,
    action: Vec<ActionSetting<'a, T>>,
    normalized_action: Option<NormalizedAction>,
    line_number: Option<u16>,
    #[serde(flatten)]
    protocol: Option<ProtocolSetting<'a>>,
    source: Vec<EndpointSetting>,
    normalized_source: Vec<IPOperator>,
    destination: Vec<EndpointSetting>,
    normalized_destination: Vec<IPOperator>,
}

impl<'a, T> ACLRule<'a, T>
where
    T: TryInto<NormalizedAction, Error = ParseEnumError> + Clone + Default,
{
    pub fn new(
        action: Vec<ActionSetting<'a, T>>,
        action_modifiers: Vec<ActionSetting<'a, T>>,
        normalized_action: Option<NormalizedAction>,
        line_number: Option<u16>,
        protocol: Option<ProtocolSetting<'a>>,
        source: Vec<EndpointSetting>,
        normalized_source: Vec<IPOperator>,
        destination: Vec<EndpointSetting>,
        normalized_destination: Vec<IPOperator>,
    ) -> Self {
        Self {
            action,
            action_modifiers,
            normalized_action,
            line_number,
            protocol,
            source,
            normalized_source,
            destination,
            normalized_destination,
        }
    }
}

impl<'a, T1> IntoPy<PyObject> for ACLRule<'a, T1>
where
    T1: IntoPy<PyObject>,
{
    fn into_py(self, py: Python) -> PyObject {
        let dict = PyDict::new(py);
        dict.set_item::<PyObject, PyObject>(
            "action_modifiers".into_py(py),
            self.action_modifiers.into_py(py),
        )
        .expect("Failed to set_item on dict");
        dict.set_item::<PyObject, PyObject>("action".into_py(py), self.action.into_py(py))
            .expect("Failed to set_item on dict");
        dict.set_item::<PyObject, PyObject>(
            "normalized_action".into_py(py),
            self.normalized_action.into_py(py),
        )
        .expect("Failed to set_item on dict");
        dict.set_item::<PyObject, PyObject>("protocol".into_py(py), self.protocol.into_py(py))
            .expect("Failed to set_item on dict");
        dict.into_py(py)
    }
}

pub struct ACLRuleBulder<'a, T> {
    action: Vec<ActionSetting<'a, T>>,
    action_modifiers: Vec<ActionSetting<'a, T>>,
    normalized_action: Option<NormalizedAction>,
    line_number: Option<u16>,
}

impl<'a, T> ACLRuleBulder<'a, T>
where
    T: TryInto<NormalizedAction, Error = ParseEnumError> + Clone + Default,
{
    pub fn new() -> Self {
        Self {
            action_modifiers: vec![],
            action: vec![],
            normalized_action: None,
            line_number: None,
        }
    }

    pub fn extend_action_modifiers(&mut self, values: Vec<ActionSetting<'a, T>>) -> &mut Self {
        self.action_modifiers.extend(values);
        self
    }

    pub fn add_action(&mut self, value: Option<ActionSetting<'a, T>>) -> &mut Self {
        value.map(|v| self.action.push(v));
        self
    }

    pub fn add_action_modifier(&mut self, value: Option<ActionSetting<'a, T>>) -> &mut Self {
        value.map(|v| self.action_modifiers.push(v));
        self
    }

    pub fn build(
        mut self,
        default: ACLRule<'a, T>,
        protocol: ProtocolSettingBuilder<'a>,
    ) -> ACLRule<'a, T> {
        self.action.is_empty().then(|| self.action = default.action);
        self.action_modifiers
            .is_empty()
            .then(|| self.action_modifiers = default.action_modifiers);
        self.normalized_action = self
            .action
            .first()
            .map(|v| v.normalized_action().ok())
            .flatten();

        ACLRule::new(
            self.action,
            self.action_modifiers,
            self.normalized_action.or(default.normalized_action),
            self.line_number.or(default.line_number),
            Some(protocol.build(default.protocol.unwrap())),
            vec![],
            vec![],
            vec![],
            vec![],
        )
    }
}

#[derive(Serialize)]
#[serde(rename_all(serialize = "PascalCase", deserialize = "snake_case"))]
pub struct EndpointSetting {
    address: IPOperator,
}
