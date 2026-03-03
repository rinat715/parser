use crate::ProtocolSetting as ProtocolSettingDomain;
use crate::{ActionSetting, ICMPOptions, IPv4Options, NormalizedAction, Protocol, TCPUDPOptions};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};
use serde_derive::Serialize;
use std::str::FromStr;

#[derive(Debug, PartialEq, Eq)]
pub struct ConvertError; // TODO нормальное название

#[derive(Debug, PartialEq, Default, Serialize, Clone)]
pub enum ActionType {
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

impl IntoPy<PyObject> for ActionType {
    fn into_py(self, py: Python) -> PyObject {
        match self {
            Self::ACCEPT => PyString::new(py, "ACCEPT").into_py(py),
            Self::DROP => PyString::new(py, "DROP").into_py(py),
            Self::LOG => PyString::new(py, "LOG").into_py(py),
            Self::NFLOG => PyString::new(py, "NFLOG").into_py(py),
            Self::QUEUE => PyString::new(py, "QUEUE").into_py(py),
            Self::REJECT => PyString::new(py, "REJECT").into_py(py),
            Self::RETURN => PyString::new(py, "RETURN").into_py(py),
            Self::GOTO => PyString::new(py, "GOTO").into_py(py),
            Self::JUMP => PyString::new(py, "JUMP").into_py(py),
            Self::PASS => PyString::new(py, "PASS").into_py(py),
            Self::LogLevel => PyString::new(py, "log-level").into_py(py),
            Self::LogPrefix => PyString::new(py, "log-prefix").into_py(py),
            Self::LogTCPSequence => PyString::new(py, "log-tcp-sequence").into_py(py),
            Self::LogTCPOptions => PyString::new(py, "log-tcp-options").into_py(py),
            Self::LogIPOptions => PyString::new(py, "log-ip-options").into_py(py),
            Self::LogUID => PyString::new(py, "log-uid").into_py(py),
        }
    }
}

#[derive(Serialize)]
pub struct ProtocolSetting<'a>(ProtocolSettingDomain<'a, IPv4Options>);
impl<'a> ProtocolSetting<'a> {
    pub fn new(
        protocol: Protocol<'a>,
        tcp_udp_options: Option<TCPUDPOptions<'a>>,
        ip_options: Option<IPv4Options>,
        icmp_options: Option<ICMPOptions>,
    ) -> Self {
        Self(ProtocolSettingDomain::new(
            None,
            protocol,
            tcp_udp_options,
            ip_options,
            icmp_options,
        ))
    }
}
impl Default for ProtocolSetting<'_> {
    fn default() -> Self {
        let protocol = Protocol::ip();
        Self(ProtocolSettingDomain::new(None, protocol, None, None, None))
    }
}

#[derive(Serialize)]
#[serde(rename_all(serialize = "PascalCase", deserialize = "snake_case"))]
pub struct ACLRule<'a, ActionType> {
    action_modifiers: Vec<ActionSetting<'a, ActionType>>,
    action: Vec<ActionSetting<'a, ActionType>>,
    normalized_action: Option<NormalizedAction>,
    #[serde(flatten)]
    protocol: Option<ProtocolSettingDomain<'a, IPv4Options>>,
}

impl<'a> ACLRule<'a, ActionType> {
    pub fn new(
        action: ActionSetting<'a, ActionType>,
        action_modifiers: Vec<ActionSetting<'a, ActionType>>,
        normalized_action: Option<NormalizedAction>,
        protocol: ProtocolSetting<'a>,
    ) -> Self {
        Self {
            action: vec![action],
            normalized_action,
            action_modifiers,
            protocol: Some(protocol.0),
        }
    }
}

impl<'a> IntoPy<PyObject> for ACLRule<'a, ActionType> {
    fn into_py(self, py: Python) -> PyObject {
        let dict = PyDict::new(py);
        dict.set_item::<PyObject, PyObject>("action_modifiers".into_py(py), self.action_modifiers.into_py(py)).expect("Failed to set_item on dict");
        dict.set_item::<PyObject, PyObject>("action".into_py(py), self.action.into_py(py)).expect("Failed to set_item on dict");
        dict.set_item::<PyObject, PyObject>("normalized_action".into_py(py), self.normalized_action.into_py(py)).expect("Failed to set_item on dict");
        dict.set_item::<PyObject, PyObject>("protocol".into_py(py), self.protocol.into_py(py)).expect("Failed to set_item on dict");
        dict.into_py(py)
    }
}

