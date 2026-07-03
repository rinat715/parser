use crate::domain::generic::Bool;
use crate::domain::{self as d, Str};
use crate::nftables::RawACLRule;
use macros::{ToDict, ToPyDict, ToSerialzeMap, ToStr, is_not_null};
use serde_derive::Serialize;
use std::collections::BTreeMap;
use std::str::FromStr;

use serde::{Serializer, ser::SerializeSeq};

#[derive(Debug)]
pub struct ConvertError; // TODO нормальное название

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


impl FromStr for ActionType {
    type Err = ConvertError; // TODO

    fn from_str(o: &str) -> Result<Self, Self::Err> {
        match o {
            "ACCEPT" => Ok(Self::ACCEPT),
            "DROP" => Ok(Self::DROP),
            "LOG" => Ok(Self::LOG),
            "NFLOG" => Ok(Self::NFLOG),
            "QUEUE" => Ok(Self::QUEUE),
            "REJECT" => Ok(Self::REJECT),
            "RETURN" => Ok(Self::RETURN),
            "GOTO" => Ok(Self::GOTO),
            "JUMP" => Ok(Self::JUMP),
            "log-level" => Ok(Self::LogLevel),
            "log-prefix" => Ok(Self::LogPrefix),
            "log-tcp-sequence" => Ok(Self::LogTCPSequence),
            "log-tcp-options" => Ok(Self::LogTCPOptions),
            "log-ip-options" => Ok(Self::LogIPOptions),
            "log-uid" => Ok(Self::LogUID),

            _ => Err(ConvertError),
        }
    }
}

impl TryInto<d::NormalizedAction> for ActionType {
    type Error = crate::domain::ParseEnumError;

    fn try_into(self) -> Result<d::NormalizedAction, Self::Error> {
        match self {
            Self::ACCEPT => Ok(d::NormalizedAction::PERMIT),
            Self::DROP | Self::REJECT => Ok(d::NormalizedAction::DENY),
            Self::JUMP | Self::GOTO => Ok(d::NormalizedAction::JUMP),
            Self::PASS => Ok(d::NormalizedAction::PASS),
            Self::RETURN => Ok(d::NormalizedAction::RETURN),

            _ => Err(crate::domain::ParseEnumError),
        }
    }
}

pub static EXCLAMATION: &str = "!";

pub type OperatorType = d::OperatorTypeGeneric<Option<&'static str>>;

impl From<OperatorType> for bool {
    fn from(val: OperatorType) -> Self {
        val.0.is_none()
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

impl Default for OperatorType {
    fn default() -> Self {
        Self(None)
    }
}

impl OperatorType {
    pub fn new(value: Option<&'static str>) -> Self {
        Self(value)
    }
}


#[derive(Serialize, Default)]
#[serde(rename_all(serialize = "PascalCase", deserialize = "snake_case"))]
pub struct NATExtended<'a> {
    #[serde(skip_serializing_if = "d::is_empty")]
    connection_states: Vec<d::StringOperator>,
    #[serde(skip_serializing_if = "d::is_empty")]
    sets: Vec<d::SetOperator>,
    network_mapped_translated_address: Option<d::IPOperator>,
    target: Option<&'a str>,
}

impl<'a> NATExtended<'a> {
    #[is_not_null(all)]
    pub fn new(
        connection_states: Vec<d::StringOperator>,
        sets: Vec<d::SetOperator>,
        network_mapped_translated_address: Option<d::IPOperator>,
        target: Option<&'a str>,
    ) -> Option<Self> {
        Some(Self {
            connection_states,
            sets,
            network_mapped_translated_address,
            target,
        })
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

pub type ACLRule = d::ACLRule<d::ACL<ActionType>, ACLExtended>;

pub type UserChain = Str;
pub type ChainName = Str;
pub type DefaultAction = Str;

#[derive(Serialize, ToPyDict)]
pub struct Chain {
    name: ChainName,
    default_action: DefaultAction,
    rules: Vec<d::nftables::ACLRule>,
}

impl Chain {
    pub fn new(name: Str, default_action: Str) -> Self {
        Self {
            name,
            default_action,
            rules: vec![],
        }
    }
}

fn to_list<S>(map: &BTreeMap<Str, Chain>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(map.len()))?;
    for element in map.values() {
        seq.serialize_element(element)?;
    }
    seq.end()
}

#[derive(Serialize, ToPyDict)]
pub struct Table {
    name: Str,
    #[serde(rename = "chains", serialize_with = "to_list")]
    chain_map: BTreeMap<Str, Chain>,
}

impl Table {
    pub fn new(name: &str) -> Self {
        let chain_map = BTreeMap::new();
        let name = Str::new(name);

        Self { name, chain_map }
    }

    pub fn set_chain_map(&mut self, value: BTreeMap<Str, Chain>) {
        self.chain_map = value
    }

    pub fn set_chain(&mut self, name: Str, default_action: Str) -> std::option::Option<Chain> {
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
    pub fn set_rule(&mut self, mut rule: RawACLRule) {
        if let Some(v) = self.chain_map.get_mut(&rule.chain) {
            rule.set_status();
            rule.set_number(v.rules.len() + 1);
            v.rules.push(rule.build());
        }
    }

    pub fn process_ruls(&mut self, values: Vec<d::Value<RawACLRule>>) {
        for item in values {
            match item {
                d::Value::Value(v) => self.set_rule(v),
                d::Value::Error(v) => println!("Error in table part {}", v.as_str()),
            };
        }
    }
}
