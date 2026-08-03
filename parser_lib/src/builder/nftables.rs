use crate::builder::{Builder, DirectionBuilder, GeneralBuilder, Mapper, ProtocolSettingBuilder};
use crate::domain as d;
use crate::part::nftables::{ACL, ACLRule, NAT, NATRule, Vendor};
use std::{cell::RefCell, rc::Rc};

use crate::domain::nftables::{Context, NATType};
use crate::nftables::{ActionSetting, ActionType};
use crate::part::Interface;

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
                    if operator {
                        self.normalized.push(d::Str::new(v));
                    };
                    self.value.push(d::StringOperator::single(operator, v));
                }
                Interface::Mask(v) => normalizator.normalize(v).iter().for_each(|v| {
                    self.value.push(d::StringOperator::single(operator, v));
                    if operator {
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
    Builder<(
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
            NATType::DNAT | NATType::REDIRECT => true,
            _ => false,
        }
    }

    fn is_translated_to_source(&self) -> bool {
        match self.type_ {
            NATType::SNAT | NATType::MASQUERADE => true,
            _ => false,
        }
    }
}

impl<'a> Mapper<NAT<'a>> for NATBuilder<'a> {
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

impl<'a> Builder<d::NAT<d::nftables::NATType>> for NATBuilder<'a> {
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

impl<'a> Mapper<ACL<'a>> for ACLBuilder<'a> {
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

impl<'a> Builder<d::ACL<ActionType>> for ACLBuilder<'a> {
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

impl Mapper<Vendor> for VendorBuilder {
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

impl Builder<d::nftables::ACLExtended> for VendorBuilder {
    fn build(self) -> d::nftables::ACLExtended {
        d::nftables::ACLExtended::new(self.connection_states, self.sets)
    }
}

impl Builder<d::nftables::NATExtended> for VendorBuilder {
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

pub type RawACLRule<'a> = RawRule<ACLBuilder<'a>>;
pub type RawNATRule<'a> = RawRule<NATBuilder<'a>>;

impl<T> RawRule<T> {
    pub fn set_number(&mut self, number: usize) {
        self.general.set_number(number);
    }

    pub fn set_status(&mut self) {
        self.general.set_status(true);
    }
}

impl<'a> Mapper<NATRule<'a>> for RawNATRule<'a> {
    fn mapping(&mut self, item: NATRule<'a>) {
        match item {
            NATRule::Error(v) => println!("Error: {:?}", v),
            NATRule::Space => (),
            NATRule::Protocol(protocol) => self.protocol.mapping(protocol),
            NATRule::General(v) => self.general.mapping(v),
            NATRule::Extended(v) => {
                if let NAT::TranslatedSource((address, port)) = v {
                    self.extended.translated_source(address);

                    if let Some(v) = port { self.protocol.set_translated_source(v); }
                    return;
                };

                if let NAT::TranslatedDestination((address, port)) = v {
                    self.extended.translated_destination(address);

                    if let Some(v) = port { self.protocol.set_translated_destination(v); }
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

            NATRule::Vendor(v) => self.vendor.mapping(v),
        };
    }
}

impl<'a> Builder<d::nftables::NATRule> for RawNATRule<'a> {
    fn build(mut self) -> d::nftables::NATRule {
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

impl<'a> Mapper<ACLRule<'a>> for RawACLRule<'a> {
    fn mapping(&mut self, item: ACLRule<'a>) {
        match item {
            ACLRule::Error(v) => println!("Error: {:?}", v),
            ACLRule::Space => (),
            ACLRule::Protocol(protocol) => self.protocol.mapping(protocol),
            ACLRule::General(v) => self.general.mapping(v),
            ACLRule::Extended(v) => self.extended.mapping(v),
            ACLRule::Vendor(v) => self.vendor.mapping(v),
        };
    }
}

impl<'a> Builder<d::nftables::ACLRule> for RawACLRule<'a> {
    fn build(mut self) -> d::nftables::ACLRule {
        self.general.protocol_setting(self.protocol.build());

        d::Rule::new(
            self.general.build(),
            self.extended.build(),
            self.vendor.build(),
        )
    }
}

impl<'a> RawACLRule<'a> {
    pub fn new(ctx: &'a Rc<RefCell<Context>>, row: &'a str, chain: &'a str) -> Self {
        let mut rule = GeneralBuilder::default();
        rule.set_raw(row);

        Self {
            protocol: ProtocolSettingBuilder::new(),
            general: rule,
            extended: ACLBuilder::new(ctx),
            vendor: VendorBuilder::default(),
            chain: d::Str::new(chain),
        }
    }
}

impl<'a> RawNATRule<'a> {
    pub fn new(ctx: &'a Rc<RefCell<Context>>, row: &str, chain: &str) -> Self {
        let mut rule = GeneralBuilder::default();
        rule.set_raw(row);

        Self {
            protocol: ProtocolSettingBuilder::new(),
            general: rule,
            extended: NATBuilder::new(ctx),
            vendor: VendorBuilder::default(),
            chain: d::Str::new(chain),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acl_builder() {
        let interfaces = vec![String::from("swp1"), String::from("swp2")];

        let context = Context::new(interfaces);

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
