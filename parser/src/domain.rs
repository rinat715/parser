use serde_derive::Serialize;

pub mod operators;
pub use operators::*;

pub mod ip;
pub use ip::*;

pub mod generic;
pub use generic::*;

pub mod nftables;

pub mod pythonize;
pub mod serialize;

use macros::{ToDict, ToStr, ToSerialzeMap};

#[derive(Debug, PartialEq, Eq)]
pub struct ParseEnumError; // TODO нормальное название

pub fn is_empty<T>(values: &Vec<T>) -> bool {
    values.is_empty()
}

use crate::domain::{Bool, Operator};

// ! --ports 50,300:400
//
//
#[derive(Clone, ToStr)]
pub enum PortType {
    #[serialize(rename = "eq")]
    EQ,
    #[serialize(rename = "neq")]
    NEQ,
    #[serialize(rename = "range")]
    RANGE,
    #[serialize(rename = "nrange")]
    NotRange,
}

#[derive(ToDict, Clone)]
#[serialize(transparent)]
pub struct PortOperator(Operator<PortType, u16>);

impl PortOperator {
    pub fn new(operator: impl Into<bool>, value: Tuple<u16>) -> Self {
        let (operator, value) = match (operator.into(), value.is_single()) {
            (true, true) => (PortType::EQ, value),
            (true, false) => (PortType::RANGE, value),
            (false, true) => (PortType::NEQ, value),
            (false, false) => (PortType::NotRange, value),
        };
        Self(Operator { operator, value })

        // Self(bool_operator(operator, value))
    }
}

pub static TCP_FLAGS_ALL: [Flag; 6] = [
    Flag::SYN,
    Flag::ACK,
    Flag::FIN,
    Flag::RST,
    Flag::URG,
    Flag::PSH,
];

// или добавить
// cwr - congestion window reduced
//ece - ECN-echo flag (explicit congestion notification)
#[derive(Clone, PartialEq, ToStr)]
pub enum Flag {
    #[serialize(rename = "SYN")]
    SYN,
    #[serialize(rename = "ACK")]
    ACK,
    #[serialize(rename = "FIN")]
    FIN,
    #[serialize(rename = "RST")]
    RST,
    #[serialize(rename = "URG")]
    URG,
    #[serialize(rename = "PSH")]
    PSH,
}

#[derive(Clone, ToDict)]
#[serialize(transparent)]
pub struct FlagOperator(Operator<Bool, Vec<Flag>>);
impl FlagOperator {
    pub fn new(operator: impl Into<bool>, values: Vec<Flag>) -> Self {
        Self(bool_operator_singe(operator, values))
    }
}

#[derive(Default, Clone, ToDict)]
pub struct TCPOption {
    #[serialize(rename = "SourcePorts")]
    source: Vec<PortOperator>,
    #[serialize(rename = "DestinationPorts")]
    destination: Vec<PortOperator>,
    #[serialize(rename = "Flags")]
    flags: Vec<FlagOperator>,
}

impl TCPOption {
    pub fn new(
        sports: Vec<PortOperator>,
        dports: Vec<PortOperator>,
        flags: Vec<FlagOperator>,
    ) -> Self {
        Self {
            source: sports,
            destination: dports,
            flags,
        }
    }

    pub fn validate(self) -> Option<Self> {
        if let (true, true, true) = (
            self.flags.is_empty(),
            self.source.is_empty(),
            self.destination.is_empty(),
        ) {
            return None;
        }
        Some(self)
    }
}

#[derive(Clone, ToDict, ToSerialzeMap)]
struct TCP {
    #[serialize(rename = "ProtocolNumber")]
    operator: Operator<Bool, u8>,
    #[serialize(rename = "TCPUDPOptions", skip_none)]
    option: Option<TCPOption>,
}

impl TCP {
    // tcp     6       TCP             # transmission control protocol
    const TYPE: (u8, &str) = (6, "TCP");

    pub fn new(operator: impl Into<bool>, options: TCPOption) -> Self {
        Self {
            operator: single_operator(operator.into(), Self::TYPE.0),
            option: options.validate(),
        }
    }
}

#[derive(Default, Clone, ToDict)]
pub struct UDPOption {
    #[serialize(rename = "SourcePorts")]
    source: Vec<PortOperator>,
    #[serialize(rename = "DestinationPorts")]
    destination: Vec<PortOperator>,
}

impl UDPOption {
    pub fn new(sports: Vec<PortOperator>, dports: Vec<PortOperator>) -> Self {
        Self {
            source: sports,
            destination: dports,
        }
    }

    pub fn validate(self) -> Option<Self> {
        if let (true, true) = (self.source.is_empty(), self.destination.is_empty()) {
            return None;
        }
        Some(self)
    }
}

#[derive(Clone, ToDict, ToSerialzeMap)]
struct UDP {
    #[serialize(rename = "ProtocolNumber")]
    operator: Operator<Bool, u8>,
    #[serialize(rename = "TCPUDPOptions", skip_none)]
    option: Option<UDPOption>,
}

impl UDP {
    // udp     17      UDP             # user datagram protocol
    const TYPE: (u8, &str) = (17, "UDP");

    pub fn new(operator: impl Into<bool>, options: UDPOption) -> Self {
        Self {
            operator: single_operator(operator.into(), Self::TYPE.0),
            option: options.validate(),
        }
    }
}

#[derive(Clone)]
enum Protocol {
    TCP(TCP),
    UDP(UDP),
    String(Operator<Bool, Str>),
    Number(Operator<Bool, u8>),
}

// any | loose-source-routing | no-record-route | no-router-alert | no-source-routing | no-timestamp | none | record-route | router-alert | strict-source-routing | timestamp
#[derive(Clone)]
pub enum IPProtocolOptions {
    ANY,
    LooseSourceRouting,
    NoRecordRoute,
    NoRouterAlert,
    NoSourceRouting,
    NoTimestamp,
    //   None,
    RecordRoute,
    RouterAlert,
    StrictSourceRouting,
    Timestamp,
}

const fn range_operator<T>(operator: bool, f: T, s: T) -> Operator<Bool, T> {
    let operator = Bool(operator);
    let value = Tuple::Pair(f, s);
    Operator { operator, value }
}

const fn single_operator<T>(operator: bool, value: T) -> Operator<Bool, T> {
    let operator = Bool(operator);
    let value = Tuple::Single(value);
    Operator { operator, value }
}

impl IPProtocolOptions {
    const ANY_OPERATOR: Operator<Bool, u8> = single_operator(true, 0);
    const LOOSE_SOURCE_ROUTING_OPERATOR: Operator<Bool, u8> = single_operator(true, 131);
    const NO_RECORD_ROUTE_OPERATOR: Operator<Bool, u8> = single_operator(false, 7);
    const NO_ROUTER_ALERT_OPERATOR: Operator<Bool, u8> = single_operator(false, 148);
    const NO_SOURCE_ROUTING_OPERATOR: Operator<Bool, u8> = range_operator(false, 131, 137);
    const NO_TIMESTAMP_OPERATOR: Operator<Bool, u8> = single_operator(false, 68);
    const RECORD_ROUTE_OPERATOR: Operator<Bool, u8> = single_operator(true, 7);
    const ROUTER_ALERT_OPERATOR: Operator<Bool, u8> = single_operator(true, 148);
    const STRICT_SOURCE_ROUTING_OPERATOR: Operator<Bool, u8> = single_operator(true, 137);
    const TIMESTAMP_OPERATOR: Operator<Bool, u8> = single_operator(true, 68);

    pub fn record_route(operator: impl Into<bool>) -> Self {
        match operator.into() {
            true => Self::RecordRoute,
            false => Self::NoRecordRoute,
        }
    }

    pub fn timestamp(operator: impl Into<bool>) -> Self {
        match operator.into() {
            true => Self::Timestamp,
            false => Self::NoTimestamp,
        }
    }
    pub fn router_alert(operator: impl Into<bool>) -> Self {
        match operator.into() {
            true => Self::RouterAlert,
            false => Self::NoRouterAlert,
        }
    }
}

// eq,gt,lt.
// ttl (integer: 0..255
//
//

#[derive(ToDict, Clone)]
#[serialize(transparent)]
pub struct PacketLength(Operator<Bool, u16>);

impl PacketLength {
    pub fn new(operator: impl Into<bool>, value: Tuple<u16>) -> Self {
        Self(bool_operator(operator, value))
    }
}

#[derive(Clone, ToStr)]
pub enum TTLOperatorType {
    #[serialize(rename = "eq")]
    EQ,
    #[serialize(rename = "gt")]
    GT,
    #[serialize(rename = "lt")]
    LT,
}

#[derive(ToDict, Clone)]
#[serialize(transparent)]
pub struct TTL(Operator<TTLOperatorType, u8>);

impl TTL {
    pub fn new(operator: impl Into<TTLOperatorType>, value: u8) -> Self {
        let operator = operator.into();
        let value = Tuple::Single(value);
        Self(Operator { operator, value })
    }
}

#[derive(Clone, ToStr)]
pub enum FragmentOperatorType {
    #[serialize(rename = "gt")]
    GT,
    #[serialize(rename = "match-any")]
    MatchAny,
}

#[derive(Clone, ToStr)]
pub struct FragmentValue(bool);

impl From<bool> for FragmentValue {
    fn from(value: bool) -> Self {
        Self(value)
    }
}

impl generic::EnumToStr for FragmentValue {
    fn to_str(&self) -> &'static str {
        match self.0 {
            true => "1",
            false => "0",
        }
    }
}

// 0 нефрагментированный пакет false
// 1 первый фрагментированный пакет true
#[derive(ToDict, Clone)]
#[serialize(transparent)]
pub struct Fragment(Operator<FragmentOperatorType, FragmentValue>);
impl Fragment {
    fn gt(operator: FragmentOperatorType) -> Self {
        let value = Tuple::Single(true.into());
        Self(Operator { operator, value })
    }

    fn match_any(operator: FragmentOperatorType) -> Self {
        let value = Tuple::Pair(false.into(), true.into());
        Self(Operator { operator, value })
    }

    pub fn new(operator: impl Into<FragmentOperatorType>) -> Self {
        let fragment = operator.into();
        match fragment {
            FragmentOperatorType::GT => Self::gt(fragment),
            FragmentOperatorType::MatchAny => Self::match_any(fragment),
        }
    }
}

#[derive(Clone, ToStr)]
pub enum DSCPOperatorType {
    #[serialize(rename = "eq")]
    EQ,
}

#[derive(ToDict, Clone)]
#[serialize(transparent)]
pub struct DSCP(Operator<DSCPOperatorType, u8>);
impl DSCP {
    pub fn new(operator: impl Into<DSCPOperatorType>, value: u8) -> Self {
        let operator = operator.into();
        let value = Tuple::Single(value);
        Self(Operator { operator, value })
    }
}

#[derive(Default, Clone, ToDict)]
pub struct IPv4Options {
    #[serialize(rename = "Fragments")]
    fragments: Option<Fragment>,
    #[serialize(rename = "DSCP")]
    dscp: Option<DSCP>,
    #[serialize(rename = "IPProtocolOptions")]
    options: Vec<IPProtocolOptions>,
    #[serialize(rename = "TTL")]
    ttl: Option<TTL>,
    #[serialize(rename = "PacketLength")]
    length: Option<PacketLength>,
}

impl IPv4Options {
    pub fn new(
        fragments: Option<Fragment>,
        dscp: Option<DSCP>,
        options: Vec<IPProtocolOptions>,
        ttl: Option<TTL>,
        length: Option<PacketLength>,
    ) -> Self {
        Self {
            fragments,
            dscp,
            options,
            ttl,
            length,
        }
    }

    pub fn validate(self) -> Option<Self> {
        if let (true, true, true, true, true) = (
            self.fragments.is_none(),
            self.dscp.is_none(),
            self.options.is_empty(),
            self.ttl.is_none(),
            self.length.is_none(),
        ) {
            return None;
        }
        Some(self)
    }
}

// TODO ProtocolSetting ipv6
#[derive(Clone)]
pub struct ProtocolSetting(Protocol, Option<IPv4Options>);

impl ProtocolSetting {
    pub fn new<'a>(
        protocol: ProtocolType,
        operator: bool,
        ip_4_options: IPv4Options,
        source: Vec<PortOperator>,
        destination: Vec<PortOperator>,
        tcp_flags: Vec<FlagOperator>,
    ) -> ProtocolSetting {
        match protocol {
            ProtocolType::String(v) => ProtocolSetting::string(operator, v, ip_4_options),
            ProtocolType::Number(v) => ProtocolSetting::number(operator, v, ip_4_options),
            ProtocolType::TCP => {
                let tcp_options = TCPOption::new(source, destination, tcp_flags);

                ProtocolSetting::tcp(operator, tcp_options, ip_4_options)
            }
            ProtocolType::UDP => {
                let udp_options = UDPOption::new(source, destination);
                ProtocolSetting::udp(operator, udp_options, ip_4_options)
            }
        }
    }

    pub fn string(operator: impl Into<bool>, name: Str, ip_options: IPv4Options) -> Self {
        Self(
            Protocol::String(single_operator(operator.into(), name)),
            ip_options.validate(),
        )
    }

    pub fn number(operator: impl Into<bool>, number: u8, ip_options: IPv4Options) -> Self {
        Self(
            Protocol::Number(single_operator(operator.into(), number)),
            ip_options.validate(),
        )
    }

    pub fn tcp(operator: impl Into<bool>, options: TCPOption, ip_options: IPv4Options) -> Self {
        let protocol = TCP::new(operator, options);
        Self(Protocol::TCP(protocol), ip_options.validate())
    }

    pub fn udp(operator: impl Into<bool>, options: UDPOption, ip_options: IPv4Options) -> Self {
        let protocol = UDP::new(operator, options);
        Self(Protocol::UDP(protocol), ip_options.validate())
    }
}

impl Default for ProtocolSetting {
    fn default() -> Self {
        Self::string(true, Str::new_static("ip"), IPv4Options::default())
    }
}

pub struct ProtocolSettingPair(ProtocolSetting, ProtocolSetting);
impl ProtocolSettingPair {
    pub fn new(value: ProtocolSetting, normalized: ProtocolSetting) -> Self {
        Self(value, normalized)
    }

    pub fn from_protocol_settings(value: ProtocolSetting) -> Self {
        Self::new(value.clone(), value)
    }

    pub fn unpack(self) -> (ProtocolSetting, ProtocolSetting) {
        (self.0, self.1)
    }
}

#[derive(Clone, Serialize)]
pub enum ProtocolType {
    String(Str),
    Number(u8),
    TCP,
    UDP,
}

impl From<u8> for ProtocolType {
    fn from(value: u8) -> Self {
        if value == TCP::TYPE.0 {
            return Self::TCP;
        }
        if value == UDP::TYPE.0 {
            return Self::UDP;
        }
        Self::Number(value)
    }
}

impl From<&str> for ProtocolType {
    fn from(value: &str) -> Self {
        if value.to_uppercase() == TCP::TYPE.1 {
            return Self::TCP;
        }
        if value.to_uppercase() == UDP::TYPE.1 {
            return Self::UDP;
        }
        if let Ok(v) = value.parse::<u8>() {
            return ProtocolType::from(v);
        }

        Self::String(Str::new(value))
    }
}
impl Default for ProtocolType {
    fn default() -> Self {
        Self::String(Str::new_static("ip"))
    }
}

#[derive(Debug, PartialEq, ToStr)]
pub enum NormalizedAction {
    #[serialize(rename = "PERMIT")]
    PERMIT,
    #[serialize(rename = "DENY")]
    DENY,
    #[serialize(rename = "JUMP")]
    JUMP,
    #[serialize(rename = "PASS")]
    PASS,
    #[serialize(rename = "RETURN")]
    RETURN,
}

pub fn normalized_action<T>(
    action_setting: &ActionSetting<T>,
) -> Result<NormalizedAction, ParseEnumError>
where
    T: TryInto<NormalizedAction, Error = ParseEnumError> + Clone + Default,
{
    action_setting.action.clone().try_into()
}

#[derive(Debug, PartialEq, ToDict)]
pub struct ActionSetting<T> {
    #[serialize(rename = "Action")]
    action: T,
    #[serialize(rename = "Option", skip_none)]
    option: Option<Str>,
}

impl<T> ActionSetting<T> {
    pub fn new(action: T, option: Option<Str>) -> Self
    where
        T: TryInto<NormalizedAction, Error = ParseEnumError> + Clone + Default,
    {
        Self { action, option }
    }
}

#[derive(Serialize, Default)]
#[serde(rename_all(serialize = "PascalCase", deserialize = "snake_case"))]
pub struct NAT {
    #[serde(skip_serializing_if = "is_empty")]
    interface_in: Vec<StringOperator>,
    #[serde(skip_serializing_if = "is_empty")]
    interface_out: Vec<StringOperator>,
}

#[derive(ToDict, ToSerialzeMap)]
pub struct ACL<T> {
    #[serialize(rename = "ActionModifiers")]
    action_modifiers: Vec<ActionSetting<T>>,
    #[serialize(rename = "Action")]
    action: Vec<ActionSetting<T>>,
    #[serialize(rename = "NormalizedAction", skip_none)]
    normalized_action: Option<NormalizedAction>,
    #[serialize(rename = "InterfaceIn")]
    interface_in: Vec<StringOperator>,
    #[serialize(rename = "NormalizedInterfaceIn")]
    normalized_interface_in: Vec<Str>,
    #[serialize(rename = "InterfaceOut")]
    interface_out: Vec<StringOperator>,
    #[serialize(rename = "NormalizedInterfaceOut")]
    normalized_interface_out: Vec<Str>,
}

impl<T> ACL<T> {
    pub fn new(
        action: Vec<ActionSetting<T>>,
        action_modifiers: Vec<ActionSetting<T>>,
        normalized_action: Option<NormalizedAction>,
        interface_in: Vec<StringOperator>,
        normalized_interface_in: Vec<Str>,
        interface_out: Vec<StringOperator>,
        normalized_interface_out: Vec<Str>,
    ) -> Self
    where
        T: TryInto<NormalizedAction, Error = ParseEnumError> + Clone + Default,
    {
        Self {
            action_modifiers,
            action,
            normalized_action,
            interface_in,
            normalized_interface_in,
            interface_out,
            normalized_interface_out,
        }
    }
}

#[derive(ToDict, ToSerialzeMap)]
pub struct Base {
    #[serialize(rename = "LineNumber")]
    line_number: usize,
    #[serialize(rename = "Raw")]
    raw: Str,
    #[serialize(rename = "Status")]
    status: bool,
    #[serialize(rename = "Protocol")]
    protocol: Vec<ProtocolSetting>,
    #[serialize(rename = "NormalizedProtocol")]
    normalized_protocol: Vec<ProtocolSetting>,
    #[serialize(rename = "Source")]
    source: Vec<EndpointSetting>,
    #[serialize(rename = "NormalizedSource")]
    normalized_source: Vec<IPOperator>,
    #[serialize(rename = "Destination")]
    destination: Vec<EndpointSetting>,
    #[serialize(rename = "NormalizedDestination")]
    normalized_destination: Vec<IPOperator>,
}

impl Base {
    pub fn new(
        line_number: usize,
        raw: Str,
        status: bool,
        protocol: Vec<ProtocolSetting>,
        normalized_protocol: Vec<ProtocolSetting>,
        source: Vec<EndpointSetting>,
        normalized_source: Vec<IPOperator>,
        destination: Vec<EndpointSetting>,
        normalized_destination: Vec<IPOperator>,
    ) -> Self {
        Self {
            line_number,
            raw,
            status,
            protocol,
            normalized_protocol,
            source,
            normalized_source,
            destination,
            normalized_destination,
        }
    }
}

pub struct ACLRule<T, T1>(Base, T, T1);
impl<T, T1> ACLRule<T, T1> {
    pub fn new(base: Base, acl: T, vendor_specific: T1) -> Self {
        Self(base, acl, vendor_specific)
    }
}

#[derive(Clone)]
pub enum EndpointSetting {
    IPOperator(IPOperator),
    // TODO ObjectGroup
}

// значение плюс нормализованное значение
pub struct EndpointSettingPair(EndpointSetting, IPOperator);
impl EndpointSettingPair {
    pub fn new(value: EndpointSetting, normalized: IPOperator) -> Self {
        Self(value, normalized)
    }

    pub fn from_ip_operator(value: IPOperator) -> Self {
        let endpoint_setting = EndpointSetting::IPOperator(value.clone());
        Self::new(endpoint_setting, value)
    }

    pub fn unpack(self) -> (EndpointSetting, IPOperator) {
        (self.0, self.1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_type() {
        let protocol_type = ProtocolType::from("tcp");

        if let ProtocolType::TCP = protocol_type {
            assert!(true)
        } else {
            assert!(false, "TCP needed")
        }
    }
}
