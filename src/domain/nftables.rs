use crate::domain::{self as d};
use pyo3::prelude::*;
use pyo3::types::PyString;
use serde_derive::Serialize;
use std::str::FromStr;

use nom::{combinator::map, error::ParseError, Parser};

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

    pub fn parser<'a, E: ParseError<&'a str>, F>(f: F) -> impl Parser<&'a str, OperatorType, E>
    where
        F: Parser<&'a str, Option<&'static str>, E>,
    {
        map(f, |value| OperatorType::new(value))
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
