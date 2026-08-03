use crate::{builder::{Builder, nftables::{RawACLRule, RawNATRule}}, domain::{self as d, EnumToStr}};
use macros::{ToDict, ToPyDict, ToSerialzeMap, ToStr};
use serde_derive::Serialize;
use std::collections::BTreeMap;


use serde::{Serializer, ser::SerializeSeq};

#[derive(Default, ToStr, Clone)]
pub enum NATType {
    #[serialize(rename = "return")]
    RETURN,
    #[serialize(rename = "jump")]
    JUMP,
    #[serialize(rename = "GOTO")]
    GOTO,
    #[serialize(rename = "overload")]
    MASQUERADE,
    #[serialize(rename = "netmap")]
    NETMAP,
    #[serialize(rename = "DNAT")]
    DNAT,
    #[serialize(rename = "SNAT")]
    SNAT,
    #[serialize(rename = "REDIRECT")]
    REDIRECT,
    #[serialize(rename = "")]
    #[default]
    NONE,
}


#[derive(Default, ToStr, Clone, PartialEq, Debug)]
pub enum ActionType {
    #[serialize(rename = "ACCEPT")]
    ACCEPT,
    #[serialize(rename = "GOTO")]
    GOTO,
    #[serialize(rename = "REJECT")]
    REJECT,
    #[serialize(rename = "QUEUE")]
    QUEUE,
    #[serialize(rename = "DROP")]
    DROP,
    #[serialize(rename = "RETURN")]
    RETURN,
    #[serialize(rename = "LOG")]
    LOG,
    #[serialize(rename = "NFLOG")]
    NFLOG,
    #[serialize(rename = "JUMP")]
    JUMP,
    #[serialize(rename = "PASS")]
    #[default]
    PASS,
    #[serialize(rename = "log-level")]
    LogLevel,
    #[serialize(rename = "log-prefix")]
    LogPrefix,
    #[serialize(rename = "log-tcp-sequence")]
    LogTCPSequence,
    #[serialize(rename = "log-tcp-options")]
    LogTCPOptions,
    #[serialize(rename = "log-ip-options")]
    LogIPOptions,
    #[serialize(rename = "log-uid")]
    LogUID,
}

impl TryInto<d::NormalizedAction> for ActionType {
    type Error = crate::domain::NormalizedActionError;

    fn try_into(self) -> Result<d::NormalizedAction, Self::Error> {
        match self {
            Self::ACCEPT => Ok(d::NormalizedAction::PERMIT),
            Self::DROP | Self::REJECT => Ok(d::NormalizedAction::DENY),
            Self::JUMP | Self::GOTO => Ok(d::NormalizedAction::JUMP),
            Self::PASS => Ok(d::NormalizedAction::PASS),
            Self::RETURN => Ok(d::NormalizedAction::RETURN),

            _ => Err(crate::domain::NormalizedActionError::new(self.to_str())),
        }
    }
}

pub static EXCLAMATION: &str = "!";

#[derive(Clone)]
#[derive(Default)]
pub struct OperatorType(Option<&'static str>);

impl From<OperatorType> for bool {
    fn from(val: OperatorType) -> Self {
        val.is_none()
    }
}

impl From<OperatorType> for d::generic::Bool {
    fn from(val: OperatorType) -> Self {
        match val.0 {
            Some(_) => d::generic::Bool(false),
            None => d::generic::Bool(true),
        }
    }
}

impl From<OperatorType> for d::FragmentOperatorType {
    fn from(val: OperatorType) -> Self {
        match val.0 {
            Some(_) => d::FragmentOperatorType::MatchAny,
            None => d::FragmentOperatorType::GT,
        }
    }
}


impl OperatorType {
    pub fn new(value: Option<&'static str>) -> Self {
        Self(value)
    }

    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }
}

#[derive(ToDict, ToSerialzeMap)]
pub struct NATExtended {
    #[serialize(rename = "ConnectionStates")]
    connection_states: Vec<d::StringOperator>,
    #[serialize(rename = "Sets")]
    sets: Vec<d::SetOperator>,
    #[serialize(rename = "NetworkMappedTranslatedAddress")]
    network_mapped_translated_address: Option<d::IPOperator>,
    #[serialize(rename = "Target")]
    target: Option<d::Str>,
}

impl NATExtended {
    pub fn new(
        connection_states: Vec<d::StringOperator>,
        sets: Vec<d::SetOperator>,
        network_mapped_translated_address: Option<d::IPOperator>,
        target: Option<d::Str>,
    ) -> Self {
        Self {
            connection_states,
            sets,
            network_mapped_translated_address,
            target,
        }
    }
}

#[derive(ToDict, ToSerialzeMap)]
pub struct ACLExtended {
    #[serialize(rename = "ConnectionStates")]
    connection_states: Vec<d::StringOperator>,
    #[serialize(rename = "Sets")]
    sets: Vec<d::SetOperator>,
}

impl ACLExtended {
    pub fn new(connection_states: Vec<d::StringOperator>, sets: Vec<d::SetOperator>) -> Self {
        Self {
            connection_states,
            sets,
        }
    }
}

pub type ActionSetting = d::ActionSetting<ActionType>;

pub type ACLRule = d::Rule<d::ACL<ActionType>, ACLExtended>;
pub type NATRule = d::Rule<d::NAT<d::nftables::NATType>, d::nftables::NATExtended>;

pub type UserChain = d::Str;
pub type ChainName = d::Str;
pub type DefaultAction = d::Str;

#[derive(Serialize)]
#[serde(untagged)]
pub enum Rule {
    ACL(ACLRule),
    NAT(NATRule),
}

#[derive(Serialize, ToPyDict)]
pub struct Chain {
    name: ChainName,
    default_action: DefaultAction,
    rules: Vec<Rule>,
}

impl Chain {
    pub fn new(name: d::Str, default_action: d::Str) -> Self {
        Self {
            name,
            default_action,
            rules: vec![],
        }
    }
}

fn to_list<S>(map: &BTreeMap<d::Str, Chain>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(map.len()))?;
    for element in map.values() {
        seq.serialize_element(element)?;
    }
    seq.end()
}

#[cfg(feature = "python")]
use pyo3::prelude::*;


#[cfg_attr(feature = "python", pyclass)]
#[derive(Serialize, Clone)]
pub struct Context {
    pub interfaces: Vec<String>,       // TODO tp_traverse?
    pub user_chain_names: Vec<String>, // TODO tp_traverse?
}

#[cfg(feature = "python")]
#[pymethods]
impl Context {
    #[new]
    pub fn new(interfaces: Vec<String>) -> Self {
        let user_chain_names = vec![];
        Self {
            interfaces,
            user_chain_names,
        }
    }

    pub fn set_user_chain_names(&mut self, values: Vec<String>) {
        self.user_chain_names = values
    }
}

#[cfg(not(feature = "python"))]
impl Context {
    pub fn new(interfaces: Vec<String>) -> Self {
        let user_chain_names = vec![];
        Self {
            interfaces,
            user_chain_names,
        }
    }

    pub fn set_user_chain_names(&mut self, values: Vec<String>) {
        self.user_chain_names = values
    }
}

#[derive(Serialize, ToPyDict)]
pub struct Table {
    name: d::Str,
    #[serde(rename = "chains", serialize_with = "to_list")]
    chain_map: BTreeMap<d::Str, Chain>,
}

impl Table {
    pub fn new(name: &str) -> Self {
        let chain_map = BTreeMap::new();
        let name = d::Str::new(name);

        Self { name, chain_map }
    }

    pub fn set_chain_map(&mut self, value: BTreeMap<d::Str, Chain>) {
        self.chain_map = value
    }

    pub fn set_chain(
        &mut self,
        name: d::Str,
        default_action: d::Str,
    ) -> std::option::Option<Chain> {
        self.chain_map
            .insert(name.clone(), Chain::new(name, default_action))
    }

    pub fn process_user_chain(&mut self, values: Vec<(UserChain, DefaultAction)>) -> Vec<String> {
        let mut user_chain_names = Vec::with_capacity(values.len());
        for item in values {
            let _ = self.set_chain(item.0.clone(), item.1);
            user_chain_names.push(item.0.as_str().to_string());
        }

        user_chain_names
    }
    // cтомость перемeщения вектора
    // For Vec<Bar>, that type is a (growable) vector on the heap. The size_of::<Vec<Bar>>() on the other hand is always just 3 * size_of::<usize>(). So that’s how much a move coss.
    pub fn process_acl_rules<'a>(&mut self, values: Vec<d::Value<RawACLRule<'a>>>) {
        for item in values {
            match item {
                d::Value::Value(mut rule) => {
                    if let Some(v) = self.chain_map.get_mut(&rule.chain) {
                        rule.set_status();
                        rule.set_number(v.rules.len() + 1);
                        v.rules.push(Rule::ACL(rule.build()));
                    }
                }
                d::Value::Error(v) => println!("Error in table part {}", v.as_str()),
            };
        }
    }


    pub fn process_nat_rules<'a>(&mut self, values: Vec<d::Value<RawNATRule<'a>>>) {
        for item in values {
            match item {
                d::Value::Value(mut rule) => {
                    if let Some(v) = self.chain_map.get_mut(&rule.chain) {
                        rule.set_status();
                        rule.set_number(v.rules.len() + 1);
                        v.rules.push(Rule::NAT(rule.build()));
                    }
                }
                d::Value::Error(v) => println!("Error in table part {}", v.as_str()),
            };
        }
    }
}
