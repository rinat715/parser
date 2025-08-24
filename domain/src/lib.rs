use serde::{ser::SerializeSeq, Serialize, Serializer};
use serde_derive::Serialize;

pub mod operators;
pub use operators::*;

pub mod ip;
pub use ip::IP;
pub mod nftables;

#[derive(Debug, PartialEq, Eq)]
pub struct ParseEnumError; // TODO нормальное название

#[allow(dead_code)]
fn ser_vec_options<S, T>(values: &Vec<Option<T>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize,
{
    let mut seq = serializer.serialize_seq(Some(values.len()))?;
    for v in values {
        match v {
            Some(v) => seq.serialize_element(v)?,
            None => seq.serialize_element("")?,
        }
    }
    seq.end()
}

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

#[derive(Serialize, Default)]
#[serde(rename_all(serialize = "PascalCase", deserialize = "snake_case"))]
pub struct TCPUDPOptions<'a> {
    #[serde(skip_serializing_if="is_empty")]
    pub source_ports: Vec<IntOperator>,
    #[serde(skip_serializing_if="is_empty")]
    pub destination_ports: Vec<IntOperator>,
    #[serde(skip_serializing_if="is_empty")]
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
    pub fn source_ports(&mut self, ports: Vec<IntOperator>) -> &mut Self {
        if !ports.is_empty() {
            self.source_ports = ports
        }
        self
    }
    pub fn destination_ports(&mut self, ports: Vec<IntOperator>) -> &mut Self {
        if !ports.is_empty() {
            self.destination_ports = ports
        }
        self
    }
    pub fn flags(&mut self, flags: Vec<StringOperator<'a>>) -> &mut Self {
        if !flags.is_empty() {
            self.flags = flags
        }
        self
    }
}

impl<'a> Builder for TCPUDPOptions<'a> {
    type Result = Self;

    fn build(self) -> Self::Result {
        self
    }
}

#[derive(Serialize)]
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

#[derive(Clone)]
pub enum StringOrU16<'a> {
    // Value
    String(&'a str),
    Number(u16),
}

impl<'a> Protocol<'a> {
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

#[derive(Debug, PartialEq, Serialize)]
pub struct ActionSetting<'a, T> {
    action: T,
    option: &'a str,
}

impl<'a, T> ActionSetting<'a, T>
where
    T: TryInto<NormalizedAction, Error = ParseEnumError> + Clone,
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
}

#[derive(Serialize, Default)]
pub struct ActionSettingBuilder<'a, T> {
    action: Option<T>,
    option: Option<&'a str>,
}

impl<'a, T> ActionSettingBuilder<'a, T>
where
    T: TryInto<NormalizedAction, Error = ParseEnumError> + Clone,
{
    pub fn action(&mut self, action: Option<T>) -> &mut Self {
        if let Some(v) = action {
            self.action = Some(v)
        }
        self
    }

    pub fn option(&mut self, option: Option<&'a str>) -> &mut Self {
        if let Some(v) = option {
            self.option = Some(v)
        }
        self
    }
}

impl<'a, T> Builder for ActionSettingBuilder<'a, T>
where
    T: TryInto<NormalizedAction, Error = ParseEnumError> + Clone,
{
    type Result = Option<ActionSetting<'a, T>>;

    fn build(self) -> Self::Result {
        if self.action.is_none() {
            None
        } else {
            Some(ActionSetting::new(
                self.action.unwrap(),
                self.option.unwrap_or_default(),
            ))
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Default)]
pub struct ACLRule<'a, T> {
    pub action_modifiers: Option<Vec<ActionSetting<'a, T>>>,
    pub action: Option<Vec<ActionSetting<'a, T>>>,
    pub normalized_action: Option<NormalizedAction>,
    pub line_number: Option<u16>,
}
