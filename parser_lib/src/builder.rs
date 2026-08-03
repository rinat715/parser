use crate::domain::ProtocolType;

pub trait Builder<T> {
    fn build(self) -> T;
}

pub trait Mapper<T> {
    fn mapping(&mut self, item: T);
}

pub mod nftables;

use crate::domain as d;

use crate::part::{General, ProtocolPart};



#[derive(Default)]
pub struct ProtocolSettingBuilder {
    //protocol
    operator: bool,
    protocol: d::ProtocolType,
    // ports
    source: Vec<d::PortOperator>,
    destination: Vec<d::PortOperator>,
    // translated ports
    translated_source: Vec<d::PortOperator>,
    translated_destination: Vec<d::PortOperator>,
    tcp_flags: Vec<d::FlagOperator>,
    // ip_v4_options
    fragments: Option<d::Fragment>,
    dscp: Option<d::DSCP>,
    options: Vec<d::IPProtocolOptions>,
    ttl: Option<d::TTL>,
    length: Option<d::PacketLength>,
}

impl<T> Mapper<ProtocolPart<T>> for ProtocolSettingBuilder
where
    bool: From<T>,
{
    fn mapping(&mut self, item: ProtocolPart<T>) {
        match item {
            // protocol
            ProtocolPart::Protocol((operator, protocol)) => self.set_protocol(operator, protocol),
            // ports
            ProtocolPart::DestinationPorts(v) => self.destination.extend(v),
            ProtocolPart::SourcePorts(v) => self.source.extend(v),
            ProtocolPart::Ports(v) => {
                self.source.extend(v.clone());
                self.destination.extend(v);
            }
            // ip4 options
            ProtocolPart::Fragment(v) => self.fragments = Some(v),
            ProtocolPart::DSCP(v) => self.dscp = Some(v),
            ProtocolPart::PacketLength(v) => self.length = Some(v),
            ProtocolPart::IPProtocolOption(v) => self.options.push(v),
            ProtocolPart::TCPFlags(v) => self.tcp_flags = vec![v.0, v.1],
            ProtocolPart::TTL(v) => self.ttl = Some(v),
        }
    }
}

impl Builder<d::ProtocolSetting> for ProtocolSettingBuilder {
    fn build(self) -> d::ProtocolSetting {
        let ip_4_options = d::IPv4Options::new(
            self.fragments,
            self.dscp,
            self.options,
            self.ttl,
            self.length,
        );

        d::ProtocolSetting::new(
            self.protocol,
            self.operator,
            ip_4_options,
            self.source,
            self.destination,
            self.tcp_flags,
        )
    }
}

impl Builder<(d::ProtocolSetting, d::ProtocolSetting)> for ProtocolSettingBuilder {
    fn build(self) -> (d::ProtocolSetting, d::ProtocolSetting) {
        let ip_4_options = d::IPv4Options::new(
            self.fragments.clone(),
            self.dscp.clone(),
            self.options.clone(),
            self.ttl.clone(),
            self.length.clone(),
        );

        let translated = d::ProtocolSetting::new(
            self.protocol.clone(),
            self.operator,
            ip_4_options,
            self.translated_source.clone(),
            self.translated_destination.clone(),
            self.tcp_flags.clone(),
        );
        (Builder::build(self), translated)
    }
}

impl ProtocolSettingBuilder {
    pub fn new() -> Self {
        Self {
            operator: true,
            protocol: ProtocolType::String(d::Str::new_static("ip")),
            ..Default::default()
        }
    }

    fn set_protocol(&mut self, operator: impl Into<bool>, kind: d::ProtocolType) {
        self.operator = operator.into();
        self.protocol = kind;
    }

    fn set_translated_source(&mut self, value: d::PortOperator) {
        self.translated_source.push(value)
    }

    fn set_translated_destination(&mut self, value: d::PortOperator) {
        self.translated_destination.push(value)
    }
}

#[derive(Default)]
struct DirectionBuilder {
    value: Vec<d::EndpointSetting>,
    normalized: Vec<d::IPOperator>,
}

impl DirectionBuilder {
    fn push(&mut self, value: d::IPOperator) {
        self.normalized.push(value.clone());
        self.value.push(d::EndpointSetting::IPOperator(value))
    }
}

#[derive(Default)]
pub struct GeneralBuilder {
    line_number: usize,
    raw: d::Str,
    status: bool,
    protocol: Vec<d::ProtocolSetting>,
    normalized_protocol: Vec<d::ProtocolSetting>,
    source: DirectionBuilder,
    destination: DirectionBuilder,
}

impl GeneralBuilder {
    pub fn set_raw(&mut self, value: &str) {
       self.raw = d::Str::new(value);
    }
}

impl Mapper<General> for GeneralBuilder {
    fn mapping(&mut self, item: General) {
        match item {
            General::Destination(v) => self.destination.push(v),
            General::Source(v) => self.source.push(v),
        }
    }
}

impl Builder<d::General> for GeneralBuilder {
    fn build(self) -> d::General {
        d::General::new(
            self.line_number,
            self.raw,
            self.status,
            self.protocol,
            self.normalized_protocol,
            self.source.value,
            self.source.normalized,
            self.destination.value,
            self.destination.normalized,
        )
    }
}

impl GeneralBuilder {
    fn protocol_setting(&mut self, value: d::ProtocolSetting) {
        self.protocol.push(value.clone());
        self.normalized_protocol.push(value);
    }
    pub fn set_number(&mut self, number: usize) {
        self.line_number = number;
    }

    pub fn set_status(&mut self, value: bool) {
        self.status = value;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_setting_builder() {
        let mut b = ProtocolSettingBuilder::new();

        b.set_protocol(true, d::ProtocolType::TCP);

        let protocol: d::ProtocolSetting = b.build();

        let expected = r#"ProtocolNumber:
  Operator: eq
  Values:
  - 6
"#;
        let actual = yaml_serde::to_string(&protocol).unwrap();

        assert_eq!(
            expected,
            actual,
            "{}",
            diff::Diff::new("None", "test_protocol_setting_builder", &actual, &expected)
        )
    }

    #[test]
    fn test_protocol_setting_builder_tcp_options() {
        let mut b = ProtocolSettingBuilder::new();

        b.set_protocol(true, d::ProtocolType::TCP);

        b.source = vec![d::PortOperator::new(true, d::Tuple::Single(1))];

        b.destination = vec![d::PortOperator::new(false, d::Tuple::Pair(1, 2))];

        let protocol: d::ProtocolSetting = b.build();

        let expected = r#"ProtocolNumber:
  Operator: eq
  Values:
  - 6
TCPUDPOptions:
  SourcePorts:
  - Operator: eq
    Values:
    - 1
  DestinationPorts:
  - Operator: nrange
    Values:
    - 1
    - 2
  Flags: []
"#;
        let actual = yaml_serde::to_string(&protocol).unwrap();

        assert_eq!(
            expected,
            actual,
            "{}",
            diff::Diff::new(
                "None",
                "test_protocol_setting_builder_tcp_options",
                &actual,
                &expected
            )
        )
    }

    }
