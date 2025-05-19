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
    JUMP,
    #[default]
    PASS,
}

impl FromStr for ActionType {
    type Err = ParseEnumError;

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