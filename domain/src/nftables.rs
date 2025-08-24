use crate::{ActionSetting, IPv4Options, NormalizedAction, ProtocolSetting};
use serde_derive::Serialize;
use std::str::FromStr;

#[derive(Debug, PartialEq, Eq)]
pub struct ConvertError; // TODO нормальное название

#[derive(Debug, PartialEq, Default, Serialize, Clone)]
pub enum ActionType {
    // времено pub
    ACCEPT,
    GOTO,
    REJECT,
    QUEUE,
    DROP,
    RETURN,
    LOG,
    NFLOG,
    JUMP,
    #[default]
    PASS,
    #[serde(rename = "log-level")]
    LogLevel,
    #[serde(rename = "log-prefix")]
    LogPrefix,
    #[serde(rename = "log-tcp-sequence")]
    LogTCPSequence,
    #[serde(rename = "log-tcp-options")]
    LogTCPOptions,
    #[serde(rename = "log-ip-options")]
    LogIPOptions,
    #[serde(rename = "log-uid")]
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

impl TryInto<NormalizedAction> for ActionType {
    type Error = crate::ParseEnumError;

    fn try_into(self) -> Result<NormalizedAction, Self::Error> {
        match self {
            Self::ACCEPT => Ok(NormalizedAction::PERMIT),
            Self::DROP | Self::REJECT => Ok(NormalizedAction::DENY),
            Self::JUMP | Self::GOTO => Ok(NormalizedAction::JUMP),
            Self::PASS => Ok(NormalizedAction::PASS),
            Self::RETURN => Ok(NormalizedAction::RETURN),

            _ => Err(crate::ParseEnumError),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all(serialize = "PascalCase", deserialize = "snake_case"))]
pub struct ACLRule<'a, T> {
    action_modifiers: Vec<ActionSetting<'a, T>>,
    action: Vec<ActionSetting<'a, T>>,
    normalized_action: Option<NormalizedAction>,
    #[serde(flatten)]
    protocol: Option<ProtocolSetting<'a, IPv4Options>>,
}

impl<'a> ACLRule<'a, ActionType> {
    pub fn new(
        action: Vec<ActionSetting<'a, ActionType>>,
        action_modifiers: Vec<ActionSetting<'a, ActionType>>,
        normalized_action: Option<NormalizedAction>,
        protocol: Option<ProtocolSetting<'a, IPv4Options>>,
    ) -> Self {
        Self {
            action,
            normalized_action,
            action_modifiers,
            protocol,
        }
    }
}
