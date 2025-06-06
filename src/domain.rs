use serde_derive::Serialize;
use std::str::FromStr;
use serde::{ Serialize, Serializer, ser::SerializeSeq};



fn ser_vec_options<S, T>(values: &Vec<Option<T>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize,
{
    let mut seq = serializer.serialize_seq(Some(values.len()))?;
    for v in values {
        match v {
            Some(v) => seq.serialize_element(v)?,
            None => seq.serialize_element("")?,
        }
    }
    seq.end()
}



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
    LogUID
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
            "log-level" => Ok(Self::LogLevel),
            "log-prefix" => Ok(Self::LogPrefix),
            "log-tcp-sequence" => Ok(Self::LogTCPSequence),
            "log-tcp-options" => Ok(Self::LogTCPOptions),
            "log-ip-options" => Ok(Self::LogIPOptions),
            "log-uid" => Ok(Self::LogUID),

            _ => Err(ParseEnumError),
        }
    }
}

#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all="lowercase")]
pub enum NormalizedAction {
    PERMIT,
    DENY,
    JUMP,
    PASS,
    RETURN 
}

impl TryFrom<&ActionType> for NormalizedAction {
    type Error = ParseEnumError; // TODO 

    fn try_from(action_type: &ActionType) -> Result<Self, Self::Error> {
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
    pub action: ActionType,
    pub option: &'a str,
}

impl<'a> ActionSetting<'a> {
    pub fn new(action: ActionType, option: &'a str) -> Self {
        Self {action: action, option: option}
    }
    
    pub fn normalized_action(&self) -> Result<NormalizedAction, ParseEnumError>  {
        NormalizedAction::try_from(&self.action)
        
    }
}

#[derive(Serialize, Clone)]
pub enum OperatorType {
    EQ,
    NEQ 
}


#[derive(Serialize)]
pub struct StringOperator<'a> {
    operator: OperatorType,
    values: Vec<&'a str>
}

impl<'a> StringOperator<'a> {
    pub fn new(operator_type: OperatorType, values: Vec<&'a str>) -> Self {
        Self { operator: operator_type, values: values }
    }
}

#[derive(Serialize)]
pub struct IntOperator {
    operator: OperatorType,
    values: Vec<u16>
}

impl IntOperator {
    pub fn new(operator_type: OperatorType, values: Vec<u16>) -> Self {
        Self { operator: operator_type, values: values }
    }
}


#[derive(Debug, PartialEq, Serialize)]
pub struct ACLRule<'a> {
    pub action_modifiers: Vec<ActionSetting<'a>>,
    pub action: Vec<ActionSetting<'a>>,
    #[serde(serialize_with = "ser_vec_options")]
    pub normalized_action:  Vec<Option<NormalizedAction>>
}

impl<'a> ACLRule<'a> {
    pub fn new(action: Vec<ActionSetting<'a>>, normalized_action: Vec<Option<NormalizedAction>>,  action_modifiers:  Vec<ActionSetting<'a>>) -> Self {
        Self {action: action, normalized_action: normalized_action, action_modifiers: action_modifiers}
    }
}