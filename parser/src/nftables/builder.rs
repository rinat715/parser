use crate::domain::Normalizator;
use std::{cell::RefCell, rc::Rc, str::FromStr};

use crate::{
    Context, domain as d,
    nftables::{ActionSetting, ActionType, Operator},
};

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
    source: Vec<d::PortOperator>,
    destination: Vec<d::PortOperator>,
    tcp_flags: Vec<d::FlagOperator>,
    // ip_v4_options
    fragments: Option<d::Fragment>,
    dscp: Option<d::DSCP>,
    options: Vec<d::IPProtocolOptions>,
    ttl: Option<d::TTL>,
    length: Option<d::PacketLength>,
}

impl ProtocolSettingBuilder {
    pub fn new() -> Self {
        Self {
            operator: true,
            ..Default::default()
        }
    }

    fn set_protocol(&mut self, operator: impl Into<bool>, kind: d::ProtocolType) {
        self.operator = operator.into();
        self.protocol = kind;
    }

    fn mapping<T>(&mut self, item: ProtocolPart<T>)
    where
        bool: From<T>,
    {
        match item {
            // protocol
            ProtocolPart::Protocol((operator, protocol)) => self.set_protocol(operator, protocol),
            // tcp udp options
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

pub enum RulePart {
    Raw(d::Str),
    LineNumber(usize),
    Status(bool),
    ProtocolSetting(d::ProtocolSetting),
    Source(d::IPOperator),
    Destination(d::IPOperator),
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

impl RulePart {
    pub fn raw(value: &str) -> Self {
        Self::Raw(d::Str::new(value))
    }
}

#[derive(Default)]
pub struct RuleBuilder {
    line_number: usize,
    raw: d::Str,
    status: bool,
    protocol: Vec<d::ProtocolSetting>,
    normalized_protocol: Vec<d::ProtocolSetting>,
    source: DirectionBuilder,
    destination: DirectionBuilder,
}

impl RuleBuilder {
    fn mapping(&mut self, item: RulePart) {
        match item {
            RulePart::Destination(v) => self.destination.push(v),
            RulePart::Source(v) => self.source.push(v),
            RulePart::Raw(v) => self.raw = v,
            RulePart::LineNumber(v) => self.line_number = v,
            RulePart::Status(v) => self.status = v,
            RulePart::ProtocolSetting(protocol_setting) => self.protocol_setting(protocol_setting),
        }
    }

    fn build(self) -> d::Base {
        d::Base::new(
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

    fn protocol_setting(&mut self, value: d::ProtocolSetting) {
        self.protocol.push(value.clone());
        self.normalized_protocol.push(value);
    }
}

pub struct InterfaceNormalizator<'a> {
    ctx: &'a Rc<RefCell<Context>>,
}

impl<'a> InterfaceNormalizator<'a> {
    pub fn new(ctx: &'a Rc<RefCell<Context>>) -> Self {
        Self { ctx }
    }
}

impl<'a> d::Normalizator for InterfaceNormalizator<'a> {
    type Arg = &'a str;
    type Result = Vec<String>;

    fn normalize(&self, value: &Self::Arg) -> Self::Result {
        let ctx = self.ctx.borrow();
        ctx.interfaces
            .iter()
            .filter(|v| v.starts_with(value))
            .cloned()
            .collect()
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

    fn jump(&mut self, value: d::Str) {
        if value == "LOG" {
            self.log = Some(d::ActionSetting::new(ActionType::LOG, None));
            return;
        };
        if value == "REJECT" {
            self.reject = Some(ActionType::REJECT);
            return;
        }
        let ctx = self.ctx.borrow();
        if ctx.user_chain_names.iter().any(|s| s == value.as_str()) {
            self.action = Some(d::ActionSetting::new(ActionType::JUMP, Some(value)));
            return;
        };
        let _ = ActionType::from_str(value.as_str())
            .map(|v| self.action = Some(d::ActionSetting::new(v, None)));
    }

    fn build(
        self,
    ) -> (
        Vec<ActionSetting>,
        Vec<ActionSetting>,
        Option<d::NormalizedAction>,
    ) {
        if let Some(log_setting) = self.log {
            let normalized_action = d::normalized_action(&log_setting).ok();
            let mut action_modifiers = vec![self.log_level];
            action_modifiers.extend(self.action_modifiers);

            return (vec![log_setting], action_modifiers, normalized_action);
        }

        if let Some(reject) = self.reject {
            let action_setting = d::ActionSetting::new(reject, self.reject_with);
            let normalized_action = d::normalized_action(&action_setting).ok();

            return (
                vec![action_setting],
                self.action_modifiers,
                normalized_action,
            );
        }

        if let Some(action_setting) = self.action {
            let normalized_action = d::normalized_action(&action_setting).ok();

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

pub enum ACLPart<'a> {
    Jump(&'a str),
    Goto(&'a str),
    RejectWith(&'a str),
    LogLevel(d::ActionSetting<ActionType>),
    ActionModifier(d::ActionSetting<ActionType>),
    InterfaceIn((bool, Vec<Interface<'a>>)),
    InterfaceOut((bool, Vec<Interface<'a>>)),
}

pub struct ACLBuilder<'a> {
    action: ActionBuilder<'a>,
    // interface_
    interface: InterfaceNormalizator<'a>,
    interface_in: InterfaceBuilder,
    interface_out: InterfaceBuilder,
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

    pub fn build(self) -> d::ACL<ActionType> {
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

    pub fn mapping(&mut self, item: ACLPart<'a>) {
        match item {
            // action
            ACLPart::Jump(v) => self.action.jump(d::Str::new(v)),
            ACLPart::Goto(v) => self.action.goto(d::Str::new(v)),
            ACLPart::RejectWith(v) => self.action.reject_with = d::Str::some(v),
            ACLPart::LogLevel(v) => self.action.log_level = v,
            ACLPart::ActionModifier(v) => self.action.action_modifiers.push(v),
            ACLPart::InterfaceIn(v) => self.interface_in.push(v.0, v.1, &self.interface),
            ACLPart::InterfaceOut(v) => self.interface_out.push(v.0, v.1, &self.interface),
        }
    }
}
pub enum ACLExtendedEnum {
    Ctstate(Vec<d::StringOperator>),
    Sets(d::SetOperator),
}

#[derive(Default)]
pub struct ACLExtendedBuilder {
    connection_states: Vec<d::StringOperator>,
    sets: Vec<d::SetOperator>,
}

impl ACLExtendedBuilder {
    pub fn mapping(&mut self, item: ACLExtendedEnum) {
        match item {
            // vendor
            ACLExtendedEnum::Ctstate(v) => self.connection_states = v,
            ACLExtendedEnum::Sets(v) => self.sets.push(v),
        }
    }
    pub fn build_acl(self) -> d::nftables::ACLExtended {
        d::nftables::ACLExtended::new(self.connection_states, self.sets)
    }
}

pub struct RawACLRule<'a> {
    // билдеры
    protocol: ProtocolSettingBuilder,
    rule: RuleBuilder,
    extended: ACLBuilder<'a>,
    vendor: ACLExtendedBuilder,
    // шаред поля
    pub chain: d::Str,
}

impl<'a> RawACLRule<'a> {
    pub fn new(ctx: &'a Rc<RefCell<Context>>, row: &'a str, chain: &'a str) -> Self {
        let mut rule = RuleBuilder::default();
        rule.mapping(RulePart::raw(row));

        Self {
            protocol: ProtocolSettingBuilder::new(),
            rule: rule,
            extended: ACLBuilder::new(ctx),
            vendor: ACLExtendedBuilder::default(),
            chain: d::Str::new(chain),
        }
    }

    pub fn mapping(&mut self, item: Token<'a>) {
        match item {
            Token::Error(v) => println!("Error: {:?}", v),
            Token::Space => (),
            Token::Protocol(protocol) => self.protocol.mapping(protocol),
            Token::Base(base_enum) => self.rule.mapping(base_enum),
            Token::ACL(acltoken) => self.extended.mapping(acltoken),
            Token::ACLExtended(aclextended_enum) => self.vendor.mapping(aclextended_enum),
        };
    }

    pub fn set_number(&mut self, number: usize) {
        self.rule.mapping(RulePart::LineNumber(number));
    }

    pub fn set_status(&mut self) {
        self.rule.mapping(RulePart::Status(true));
    }

    pub fn build(mut self) -> d::ACLRule<d::ACL<ActionType>, d::nftables::ACLExtended> {
        self.rule
            .mapping(RulePart::ProtocolSetting(self.protocol.build()));

        d::ACLRule::new(
            self.rule.build(),
            self.extended.build(),
            self.vendor.build_acl(),
        )
    }
}

pub enum Token<'a> {
    Protocol(ProtocolPart<Operator>),
    Base(RulePart),
    ACL(ACLPart<'a>),
    ACLExtended(ACLExtendedEnum),
    Error(&'a str),
    Space,
}

impl<'a> Token<'a> {
    pub fn space(_: &'a str) -> Self {
        Token::Space
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_setting_builder() {
        let mut b = ProtocolSettingBuilder::new();

        b.set_protocol(true, d::ProtocolType::TCP);

        let protocol = b.build();

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

        let protocol = b.build();

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

        b.action.jump(d::Str::new("LOG"));

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
