use serde_derive::Serialize;

use crate::domain::generic::Builder;
use crate::domain::nftables::NATType;
use crate::domain::{Mapper, ProtocolType, generic};
use std::{cell::RefCell, rc::Rc};

use crate::{
    Context, domain as d,
    nftables::{ActionSetting, ActionType, Operator},
};

#[derive(Serialize)]
pub enum Address {
    Network((d::IP, u8)),
    IP(d::IP),
    Range((d::IP, d::IP)),
}

impl Address {
    pub fn ip_operator<T>(self, operator: T) -> d::IPOperator
    where
        bool: From<T>,
    {
        match self {
            Self::Network((ip, prefix)) => d::IPOperator::ip4_address(operator, ip, prefix),
            Self::IP(ip) => d::IPOperator::ip(operator, ip),
            Self::Range((f, s)) => d::IPOperator::ip_range(operator, (f, s)),
        }
    }
}

pub enum ProtocolPart<T> {
    DestinationPorts(Vec<d::PortOperator>),
    Ports(Vec<d::PortOperator>),
    Protocol((T, d::ProtocolType)),
    SourcePorts(Vec<d::PortOperator>),
    TCPFlags((d::FlagOperator, d::FlagOperator)),
    TTL(d::TTL),
    Fragment(d::Fragment),
    DSCP(d::DSCP),
    PacketLength(d::PacketLength),
    IPProtocolOption(d::IPProtocolOptions),
}

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

impl<T> generic::Mapper<ProtocolPart<T>> for ProtocolSettingBuilder
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

impl generic::Builder<d::ProtocolSetting> for ProtocolSettingBuilder {
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

impl generic::Builder<(d::ProtocolSetting, d::ProtocolSetting)> for ProtocolSettingBuilder {
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
            self.operator.clone(),
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

pub enum General {
    Raw(d::Str),
    Source(d::IPOperator),
    Destination(d::IPOperator),
}

impl General {
    pub fn raw(value: &str) -> Self {
        Self::Raw(d::Str::new(value))
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

impl generic::Mapper<General> for GeneralBuilder {
    fn mapping(&mut self, item: General) {
        match item {
            General::Destination(v) => self.destination.push(v),
            General::Source(v) => self.source.push(v),
            General::Raw(v) => self.raw = v,
        }
    }
}

impl generic::Builder<d::General> for GeneralBuilder {
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

pub struct InterfaceNormalizator<'a> {
    ctx: &'a Rc<RefCell<Context>>,
}

impl<'a> InterfaceNormalizator<'a> {
    pub fn new(ctx: &'a Rc<RefCell<Context>>) -> Self {
        Self { ctx }
    }

    fn normalize(&self, value: &'a str) -> Vec<String> {
        let ctx = self.ctx.borrow();
        ctx.interfaces
            .iter()
            .filter(|v| v.starts_with(value))
            .cloned()
            .collect()
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

pub enum Interface<'a> {
    Value(&'a str),
    Mask(&'a str),
}

#[derive(Default)]
pub struct InterfaceBuilder {
    value: Vec<d::StringOperator>,
    normalized: Vec<d::Str>,
}

impl InterfaceBuilder {
    fn push<'a>(
        &mut self,
        operator: bool,
        values: Vec<Interface<'a>>,
        normalizator: &InterfaceNormalizator<'a>,
    ) {
        for value in values {
            match value {
                Interface::Value(v) => {
                    if operator == true {
                        self.normalized.push(d::Str::new(v));
                    };
                    self.value.push(d::StringOperator::single(operator, v));
                }
                Interface::Mask(v) => normalizator.normalize(&v).iter().for_each(|v| {
                    self.value.push(d::StringOperator::single(operator, v));
                    if operator == true {
                        self.normalized.push(d::Str::new(v));
                    }
                }),
            }
        }
    }
}

struct ActionBuilder<'a> {
    ctx: &'a Rc<RefCell<Context>>,

    action_modifiers: Vec<ActionSetting>,
    action: Option<ActionSetting>,

    reject: Option<ActionType>,
    reject_with: Option<d::Str>,

    log: Option<d::ActionSetting<ActionType>>,
    log_level: d::ActionSetting<ActionType>,
}

impl<'a>
    generic::Builder<(
        Vec<ActionSetting>,
        Vec<ActionSetting>,
        Option<d::NormalizedAction>,
    )> for ActionBuilder<'a>
{
    fn build(
        self,
    ) -> (
        Vec<ActionSetting>,
        Vec<ActionSetting>,
        Option<d::NormalizedAction>,
    ) {
        if let Some(log_setting) = self.log {
            let normalized_action = d::ActionSetting::normalized_action(&log_setting).ok();
            let mut action_modifiers = vec![self.log_level];
            action_modifiers.extend(self.action_modifiers);

            return (vec![log_setting], action_modifiers, normalized_action);
        }

        if let Some(reject) = self.reject {
            let action_setting = d::ActionSetting::new(reject, self.reject_with);
            let normalized_action = d::ActionSetting::normalized_action(&action_setting).ok();

            return (
                vec![action_setting],
                self.action_modifiers,
                normalized_action,
            );
        }

        if let Some(action_setting) = self.action {
            let normalized_action = d::ActionSetting::normalized_action(&action_setting).ok();

            return (
                vec![action_setting],
                self.action_modifiers,
                normalized_action,
            );
        };
        (
            vec![d::ActionSetting::new(ActionType::PASS, None)],
            vec![],
            Some(d::NormalizedAction::PASS),
        )
    }
}

impl<'a> ActionBuilder<'a> {
    fn new(ctx: &'a Rc<RefCell<Context>>) -> Self {
        Self {
            ctx,
            log_level: ActionSetting::new(
                d::nftables::ActionType::LogLevel,
                Some(d::Str::new_static("warning")),
            ),
            action_modifiers: vec![],
            action: None,
            reject: None,
            reject_with: None,
            log: None,
        }
    }

    fn goto(&mut self, value: d::Str) {
        self.action = Some(d::ActionSetting::new(ActionType::GOTO, Some(value)));
    }

    fn set_action(&mut self, value: ActionType) {
        if let ActionType::LOG = value {
            self.log = Some(d::ActionSetting::new(ActionType::LOG, None));
            return;
        };

        if let ActionType::REJECT = value {
            self.reject = Some(ActionType::REJECT);
            return;
        };
        self.action = Some(d::ActionSetting::new(value, None));
    }

    fn jump(&mut self, value: d::Str) {
        let ctx = self.ctx.borrow();
        if ctx.user_chain_names.iter().any(|s| s == value.as_str()) {
            self.action = Some(d::ActionSetting::new(ActionType::JUMP, Some(value)));
        };
    }
}

pub enum ACL<'a> {
    Action(ActionType),
    Jump(&'a str),
    Goto(&'a str),
    RejectWith(&'a str),
    LogLevel(d::ActionSetting<ActionType>),
    ActionModifier(d::ActionSetting<ActionType>),
    InterfaceIn((bool, Vec<Interface<'a>>)),
    InterfaceOut((bool, Vec<Interface<'a>>)),
}

pub enum NAT<'a> {
    Type(d::nftables::NATType),
    Jump(&'a str),
    Goto(&'a str),
    InterfaceIn((bool, Vec<Interface<'a>>)),
    InterfaceOut((bool, Vec<Interface<'a>>)),
    TranslatedSource((d::IPOperator, Option<d::PortOperator>)),
    TranslatedDestination((d::IPOperator, Option<d::PortOperator>)),
    TranslatedPort(d::PortOperator),
}

pub struct NATBuilder<'a> {
    ctx: &'a Rc<RefCell<Context>>,
    type_: NATType,
    target: d::Str,
    interface: InterfaceNormalizator<'a>,
    interface_in: InterfaceBuilder,
    interface_out: InterfaceBuilder,
    translated_protocol: Vec<d::ProtocolSetting>,
    normalized_translated_protocol: Vec<d::ProtocolSetting>,
    translated_source: DirectionBuilder,
    translated_destination: DirectionBuilder,
}

impl<'a> NATBuilder<'a> {
    pub fn new(ctx: &'a Rc<RefCell<Context>>) -> Self {
        Self {
            ctx,
            type_: NATType::default(),
            target: d::Str::new_static(""),
            interface: InterfaceNormalizator::new(ctx),
            interface_in: InterfaceBuilder::default(),
            interface_out: InterfaceBuilder::default(),
            translated_protocol: vec![],
            normalized_translated_protocol: vec![],
            translated_source: DirectionBuilder::default(),
            translated_destination: DirectionBuilder::default(),
        }
    }

    fn translated_protocol_setting(&mut self, value: d::ProtocolSetting) {
        self.translated_protocol.push(value.clone());
        self.normalized_translated_protocol.push(value);
    }

    fn translated_source(&mut self, value: d::IPOperator) {
        self.translated_source.push(value);
    }

    fn translated_destination(&mut self, value: d::IPOperator) {
        self.translated_destination.push(value);
    }

    fn is_translated_to_destination(&self) -> bool {
        match self.type_ {
            NATType::DNAT | NATType::REDIRECT => return true,
            _ => return false,
        }
    }

    fn is_translated_to_source(&self) -> bool {
        match self.type_ {
            NATType::SNAT | NATType::MASQUERADE => return true,
            _ => return false,
        }
    }
}

impl<'a> generic::Mapper<NAT<'a>> for NATBuilder<'a> {
    fn mapping(&mut self, item: NAT<'a>) {
        match item {
            NAT::Type(v) => self.type_ = v,
            NAT::Jump(v) => {
                let ctx = self.ctx.borrow();
                if ctx.user_chain_names.iter().any(|s| s == v) {
                    self.type_ = NATType::JUMP;
                    self.target = d::Str::new(v);
                }
            }
            NAT::Goto(v) => {
                self.type_ = NATType::GOTO;
                self.target = d::Str::new(v);
            }
            NAT::InterfaceIn(v) => self.interface_in.push(v.0, v.1, &self.interface),
            NAT::InterfaceOut(v) => self.interface_out.push(v.0, v.1, &self.interface),

            _ => panic!("unreachable!"),
        }
    }
}

impl<'a> generic::Builder<d::NAT<d::nftables::NATType>> for NATBuilder<'a> {
    fn build(self) -> d::NAT<d::nftables::NATType> {
        d::NAT::new(
            self.type_,
            self.translated_protocol,
            self.normalized_translated_protocol,
            self.translated_source.value,
            self.translated_source.normalized,
            self.translated_destination.value,
            self.translated_destination.normalized,
            self.interface_in.normalized,
            self.interface_out.normalized,
        )
    }
}

pub struct ACLBuilder<'a> {
    action: ActionBuilder<'a>,
    // interface_
    interface: InterfaceNormalizator<'a>,
    interface_in: InterfaceBuilder,
    interface_out: InterfaceBuilder,
}

impl<'a> generic::Mapper<ACL<'a>> for ACLBuilder<'a> {
    fn mapping(&mut self, item: ACL<'a>) {
        match item {
            // action
            ACL::Action(v) => self.action.set_action(v),
            ACL::Jump(v) => self.action.jump(d::Str::new(v)),
            ACL::Goto(v) => self.action.goto(d::Str::new(v)),
            ACL::RejectWith(v) => self.action.reject_with = d::Str::some(v),
            ACL::LogLevel(v) => self.action.log_level = v,
            ACL::ActionModifier(v) => self.action.action_modifiers.push(v),
            ACL::InterfaceIn(v) => self.interface_in.push(v.0, v.1, &self.interface),
            ACL::InterfaceOut(v) => self.interface_out.push(v.0, v.1, &self.interface),
        }
    }
}

impl<'a> generic::Builder<d::ACL<ActionType>> for ACLBuilder<'a> {
    fn build(self) -> d::ACL<ActionType> {
        let (action_setting, action_modifiers, normalized_action) = self.action.build();

        d::ACL::new(
            action_setting,
            action_modifiers,
            normalized_action,
            self.interface_in.value,
            self.interface_in.normalized,
            self.interface_out.value,
            self.interface_out.normalized,
        )
    }
}

impl<'a> ACLBuilder<'a> {
    pub fn new(ctx: &'a Rc<RefCell<Context>>) -> Self {
        Self {
            action: ActionBuilder::new(ctx),
            interface: InterfaceNormalizator::new(ctx),
            interface_in: InterfaceBuilder::default(),
            interface_out: InterfaceBuilder::default(),
        }
    }
}

pub enum Vendor {
    Ctstate(Vec<d::StringOperator>),
    Sets(d::SetOperator),
    NetworkMappedTranslatedAddress(d::IPOperator),
}

#[derive(Default)]
pub struct VendorBuilder {
    connection_states: Vec<d::StringOperator>,
    sets: Vec<d::SetOperator>,
    network_mapped_translated_address: Option<d::IPOperator>,
    target: Option<d::Str>,
}

impl VendorBuilder {
    fn set_target(&mut self, value: Option<d::Str>) {
        self.target = value
    }
}

impl generic::Mapper<Vendor> for VendorBuilder {
    fn mapping(&mut self, item: Vendor) {
        match item {
            // vendor
            Vendor::Ctstate(v) => self.connection_states = v,
            Vendor::Sets(v) => self.sets.push(v),
            Vendor::NetworkMappedTranslatedAddress(v) => {
                self.network_mapped_translated_address = Some(v)
            }
        }
    }
}

impl generic::Builder<d::nftables::ACLExtended> for VendorBuilder {
    fn build(self) -> d::nftables::ACLExtended {
        d::nftables::ACLExtended::new(self.connection_states, self.sets)
    }
}

impl generic::Builder<d::nftables::NATExtended> for VendorBuilder {
    fn build(self) -> d::nftables::NATExtended {
        d::nftables::NATExtended::new(
            self.connection_states,
            self.sets,
            self.network_mapped_translated_address,
            self.target,
        )
    }
}

pub struct RawRule<T> {
    // билдеры
    protocol: ProtocolSettingBuilder,
    general: GeneralBuilder,
    extended: T,
    vendor: VendorBuilder,
    // шаред поля
    pub chain: d::Str,
}

impl<T> RawRule<T> {
    pub fn set_number(&mut self, number: usize) {
        self.general.set_number(number);
    }

    pub fn set_status(&mut self) {
        self.general.set_status(true);
    }
}

impl<'a> generic::Mapper<Rule<'a, NAT<'a>>> for RawRule<NATBuilder<'a>> {
    fn mapping(&mut self, item: Rule<'a, NAT<'a>>) {
        match item {
            Rule::Error(v) => println!("Error: {:?}", v),
            Rule::Space => (),
            Rule::Protocol(protocol) => self.protocol.mapping(protocol),
            Rule::General(v) => self.general.mapping(v),
            Rule::Extended(v) => {
                if let NAT::TranslatedSource((address, port)) = v {
                    self.extended.translated_source(address);

                    port.map(|v| {
                        self.protocol.set_translated_source(v);
                    });
                    return;
                };

                if let NAT::TranslatedDestination((address, port)) = v {
                    self.extended.translated_destination(address);

                    port.map(|v| {
                        self.protocol.set_translated_destination(v);
                    });
                    return;
                };

                if let NAT::TranslatedPort(port) = v {
                    if self.extended.is_translated_to_destination() {
                        self.protocol.set_translated_destination(port);
                        return;
                    };

                    if self.extended.is_translated_to_source() {
                        self.protocol.set_translated_source(port);
                        return;
                    }
                    return;
                }

                self.extended.mapping(v);
            }

            Rule::Vendor(v) => self.vendor.mapping(v),
        };
    }
}

impl<'a> generic::Builder<d::Rule<d::NAT<d::nftables::NATType>, d::nftables::NATExtended>>
    for RawRule<NATBuilder<'a>>
{
    fn build(mut self) -> d::Rule<d::NAT<d::nftables::NATType>, d::nftables::NATExtended> {
        let (protocol, translated_protocol) = self.protocol.build();
        if self.extended.is_translated_to_destination() || self.extended.is_translated_to_source() {
            self.extended
                .translated_protocol_setting(translated_protocol);
        };
        self.general.protocol_setting(protocol);

        self.vendor.set_target(Some(self.extended.target.clone()));

        d::Rule::new(
            self.general.build(),
            self.extended.build(),
            self.vendor.build(),
        )
    }
}

impl<'a> generic::Mapper<Rule<'a, ACL<'a>>> for RawRule<ACLBuilder<'a>> {
    fn mapping(&mut self, item: Rule<'a, ACL<'a>>) {
        match item {
            Rule::Error(v) => println!("Error: {:?}", v),
            Rule::Space => (),
            Rule::Protocol(protocol) => self.protocol.mapping(protocol),
            Rule::General(v) => self.general.mapping(v),
            Rule::Extended(v) => self.extended.mapping(v),
            Rule::Vendor(v) => self.vendor.mapping(v),
        };
    }
}

impl<'a> generic::Builder<d::Rule<d::ACL<ActionType>, d::nftables::ACLExtended>>
    for RawRule<ACLBuilder<'a>>
{
    fn build(mut self) -> d::Rule<d::ACL<ActionType>, d::nftables::ACLExtended> {
        self.general.protocol_setting(self.protocol.build());

        d::Rule::new(
            self.general.build(),
            self.extended.build(),
            self.vendor.build(),
        )
    }
}

impl<'a> RawRule<ACLBuilder<'a>> {
    pub fn new(ctx: &'a Rc<RefCell<Context>>, row: &'a str, chain: &'a str) -> Self {
        let mut rule = GeneralBuilder::default();
        rule.mapping(General::raw(row));

        Self {
            protocol: ProtocolSettingBuilder::new(),
            general: rule,
            extended: ACLBuilder::new(ctx),
            vendor: VendorBuilder::default(),
            chain: d::Str::new(chain),
        }
    }
}

impl<'a> RawRule<crate::nftables::builder::NATBuilder<'a>> {
    pub fn new(ctx: &'a Rc<RefCell<Context>>, row: &str, chain: &str) -> Self {
        let mut rule = GeneralBuilder::default();
        rule.mapping(General::raw(row));

        Self {
            protocol: ProtocolSettingBuilder::new(),
            general: rule,
            extended: NATBuilder::new(ctx),
            vendor: VendorBuilder::default(),
            chain: d::Str::new(chain),
        }
    }
}

pub type RawACLRule<'a> = RawRule<crate::nftables::builder::ACLBuilder<'a>>;
pub type RawNATRule<'a> = RawRule<crate::nftables::builder::NATBuilder<'a>>;

pub enum Rule<'a, T> {
    Protocol(ProtocolPart<Operator>),
    General(General),
    Extended(T),
    Vendor(Vendor),
    Error(&'a str),
    Space,
}

impl<'a, T> Rule<'a, T> {
    pub fn space(_: &'a str) -> Self {
        Rule::Space
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

    #[test]
    fn test_acl_builder() {
        let interfaces = vec![String::from("swp1"), String::from("swp2")];

        let context = Context::new(interfaces, vec![]);

        let ctx: Rc<RefCell<_>> = Rc::new(RefCell::new(context));

        let mut b = ACLBuilder::new(&ctx);

        b.action.set_action(ActionType::LOG);

        let res = b.build();

        let expected = r#"ActionModifiers:
- Action: log-level
  Option: warning
Action:
- Action: LOG
InterfaceIn: []
NormalizedInterfaceIn: []
InterfaceOut: []
NormalizedInterfaceOut: []
"#;
        let actual = yaml_serde::to_string(&res).unwrap();

        assert_eq!(
            expected,
            actual,
            "{}",
            diff::Diff::new("None", "test_acl_builder", &actual, &expected)
        )
    }
}
