use serde_derive::Serialize;
use std::str::FromStr;

#[derive(Debug, PartialEq, Eq)]
pub struct ParseEnumError;

#[derive(Debug, PartialEq, Default, Serialize)]
pub enum ActionType {
    ACCEPT,
    GOTO,
    REJECT,
    QUEUE,
    DROP,
    RETURN,
    LOG,
    NFLOG,
    #[default]
    PASS,
}

impl FromStr for ActionType {
    type Err = ParseEnumError;

    fn from_str(o: &str) -> Result<Self, Self::Err> {
        match o {
            "ACCEPT" => Ok(Self::ACCEPT),
            "GOTO" => Ok(Self::GOTO),
            "REJECT" => Ok(Self::REJECT),
            "DROP" => Ok(Self::DROP),
            "QUEUE" => Ok(Self::QUEUE),
            "RETURN" => Ok(Self::RETURN),
            "LOG" => Ok(Self::LOG),
            "NFLOG" => Ok(Self::NFLOG),

            _ => Err(ParseEnumError),
        }
    }
}

#[derive(Debug, PartialEq, Default, Serialize)]
pub struct ActionSetting<'a> {
    action: ActionType,
    option: &'a str,
}

impl<'a> ActionSetting<'a> {
    pub fn new(action: ActionType, option: &'a str) -> Self {
        Self {action: action, option: option}
    }
}

#[derive(Debug, PartialEq, Default, Serialize)]
pub struct ACLRule<'a> {
    action_modifiers: Vec<ActionSetting<'a>>,
    name: &'a str,
    action: Vec<ActionSetting<'a>>,
}