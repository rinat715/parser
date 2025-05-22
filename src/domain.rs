use serde_derive::Serialize;
use std::str::FromStr;

#[derive(Debug, PartialEq, Eq)]
pub struct ParseEnumError; // TODO нормальное название 

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
    type Err = ParseEnumError; // TODO 

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

#[derive(Debug, PartialEq, Serialize)]
pub enum NormalizedAction {
    PERMIT,
    DENY,
    JUMP,
    PASS,
    RETURN 
}

impl TryFrom<ActionType> for NormalizedAction {
    type Error = ParseEnumError; // TODO 

    fn try_from(action_type: ActionType) -> Result<Self, Self::Error> {
        match action_type {
            ActionType::ACCEPT => Ok(Self::PERMIT),
            ActionType::DROP |
            ActionType::REJECT => Ok(Self::DENY),
            ActionType::JUMP |
            ActionType::GOTO => Ok(Self::JUMP),
            ActionType::PASS => Ok(Self::PASS),
            ActionType::RETURN => Ok(Self::RETURN),

            _ => Err(ParseEnumError),

        }
        
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub struct ActionSetting<'a> {
    action: ActionType,
    option: &'a str,
}

impl<'a> ActionSetting<'a> {
    pub fn new(action: ActionType, option: &'a str) -> Self {
        Self {action: action, option: option}
    }
}


#[derive(Debug, PartialEq, Serialize)]
pub struct ACLRule<'a> {
    action_modifiers: Vec<ActionSetting<'a>>,
    name: &'a str,
    action: Vec<ActionSetting<'a>>,
    normalized_action:  Vec<NormalizedAction>
}

impl<'a> ACLRule<'a> {
    pub fn new(action: ActionSetting<'a>, normalized_action: NormalizedAction,  name: &'a str) -> Self {
        Self {action: vec![action], normalized_action: vec![normalized_action], name: name, action_modifiers: vec![]}
    }
}