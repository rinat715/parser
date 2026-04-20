use crate::domain::{self as d};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};
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

impl IntoPy<PyObject> for ActionType {
    fn into_py(self, py: Python) -> PyObject {
        let res = match self {
            Self::ACCEPT => PyString::new(py, "ACCEPT"),
            Self::DROP => PyString::new(py, "DROP"),
            Self::LOG => PyString::new(py, "LOG"),
            Self::NFLOG => PyString::new(py, "NFLOG"),
            Self::QUEUE => PyString::new(py, "QUEUE"),
            Self::REJECT => PyString::new(py, "REJECT"),
            Self::RETURN => PyString::new(py, "RETURN"),
            Self::GOTO => PyString::new(py, "GOTO"),
            Self::JUMP => PyString::new(py, "JUMP"),
            Self::PASS => PyString::new(py, "PASS"),
            Self::LogLevel => PyString::new(py, "log-level"),
            Self::LogPrefix => PyString::new(py, "log-prefix"),
            Self::LogTCPSequence => PyString::new(py, "log-tcp-sequence"),
            Self::LogTCPOptions => PyString::new(py, "log-tcp-options"),
            Self::LogIPOptions => PyString::new(py, "log-ip-options"),
            Self::LogUID => PyString::new(py, "log-uid"),
        };
        res.into_py(py)
    }
}

pub static EXCLAMATION: &str = "!";

pub type OperatorType = d::OperatorTypeGeneric<Option<&'static str>>;

impl Default for OperatorType {
    fn default() -> Self {
        Self(None)
    }
}

impl OperatorType {
    pub fn new(value: Option<&'static str>) -> Self {
        Self(value)
    }

    pub fn fragment_operator(&self) -> d::IntOperator {
        match self.0 {
            Some(_) => d::IntOperator::new(d::OperatorType::MatchAny, vec![0, 1]),
            None => d::IntOperator::new(d::OperatorType::GT, vec![1]),
        }
    }
}

impl crate::domain::BuildOperatorType for OperatorType {
    fn single(&self) -> crate::domain::OperatorType {
        match self.0 {
            Some(_) => crate::domain::OperatorType::NEQ,
            None => crate::domain::OperatorType::EQ,
        }
    }

    fn range(&self) -> crate::domain::OperatorType {
        match self.0 {
            Some(_) => crate::domain::OperatorType::NotRange,
            None => crate::domain::OperatorType::RANGE,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all(serialize = "PascalCase", deserialize = "snake_case"))]
pub struct Vendor<'a> {
    #[serde(skip_serializing_if = "d::is_empty")]
    connection_states: Vec<d::StringOperator<'a>>,
    #[serde(skip_serializing_if = "d::is_empty")]
    sets: Vec<d::SetOperator<'a>>,
}

impl<'a> Vendor<'a> {
    pub fn new(
        connection_states: Vec<d::StringOperator<'a>>,
        sets: Vec<d::SetOperator<'a>>,
    ) -> Self {
        Self {
            connection_states: connection_states,
            sets: sets,
        }
    }
}

impl<'a> IntoPy<PyObject> for Vendor<'a> {
    fn into_py(self, py: Python) -> PyObject {
        let l = PyList::new(
            py,
            &[
                ("ConnectionStates", self.connection_states.into_py(py)),
                ("Sets", self.sets.into_py(py)),
            ],
        );
        let dict = PyDict::from_sequence(py, l.into()).unwrap();
        dict.into_py(py) // Py_INCREF
    }
}

pub struct VendorBulder<'a> {
    connection_states: Vec<d::StringOperator<'a>>,
    sets: Vec<d::SetOperator<'a>>,
}

impl<'a> VendorBulder<'a> {
    pub fn new() -> Self {
        Self {
            connection_states: vec![],
            sets: vec![],
        }
    }

    pub fn extend_connection_states(&mut self, values:  Vec<d::StringOperator<'a>>) -> &mut Self {
        self.connection_states.extend(values);
        self
    }

    pub fn add_set(&mut self, value: Option<d::SetOperator<'a>>) -> &mut Self {
        value.map(|v| self.sets.push(v));
        self
    }

    pub fn build(mut self, default: Vendor<'a>) -> Vendor<'a> {
        self.connection_states
            .is_empty()
            .then(|| self.connection_states = default.connection_states);
        self.sets.is_empty().then(|| self.sets = default.sets);

        Vendor::new(self.connection_states, self.sets)
    }
}

pub type ActionSetting<'a> = d::ActionSetting<'a, ActionType>;

pub type ACLRule<'a> = d::ACLRule<'a, ActionType, Vendor<'a>>;
