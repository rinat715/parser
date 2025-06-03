use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::{alpha1, not_line_ending, space1, u8},
    combinator::map,
    multi::many1,
    sequence::{preceded, tuple},
    IResult, Parser,
};
use serde::{ser::SerializeMap, Serialize, Serializer};
use std::str::FromStr;

mod domain;
use domain as d;

#[derive(Debug, PartialEq, Eq)]
pub struct ParseEnum2Error; // TODO нормальное название

#[cfg(test)]
mod tests {
    use super::*;
    use tester::tester;

    #[tester("acl.toml")]
    fn test_rule(arg: &str) -> IResult<&str, d::ACLRule> {
        let v = vec!["MY_CHAIN"];
        rule(arg, &v)
    }

    #[tester("parser.toml")]
    fn test_parser(arg: &str) -> IResult<&str, Tokens> {
        parser(arg)
    }

    #[tester("protocol.toml")]
    fn test_protocol(arg: &str) -> IResult<&str, Tokens> {
        protocol(arg).map(|(remaining, value)| (remaining, Tokens(vec![value])))
    }

    #[test]
    fn test_jump() {
        let v = vec!["MY_CHAIN"];
        assert!(v.contains(&"MY_CHAIN"));
        let mut bulder = ActionSettingBuilder::new();
        bulder.jump("MY_CHAIN", &v);
        let res = bulder.build();
        assert_eq!(res.action, d::ActionType::JUMP);
        assert_eq!(res.option, "MY_CHAIN");
    }
}

fn until_eof(s: &str) -> IResult<&str, &str> {
    let is_next = alt((take_until(" !"), take_until(" -")));

    alt((is_next, not_line_ending))(s)
}

fn is_tag(arg: &'static str) -> impl Fn(&str) -> IResult<&str, (&str, &str)> {
    move |input: &str| tuple((tag(arg), space1)).parse(input)
}

fn value(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded(is_tag(arg), until_eof).parse(input)
}

fn rstrip_value(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded(space1, value(arg)).parse(input)
}

fn rstrip_tag(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded(space1, tag(arg)).parse(input)
}

fn unknown_part(input: &str) -> IResult<&str, Token> {
    preceded(space1, until_eof)
        .map(|value| Token::Error(value))
        .parse(input)
}

#[derive(Clone)]
enum Result<'a> {
    String(&'a str),
    Int(u8),
}

fn protocol_value(s: &str) -> IResult<&str, Result> {
    alt((
        map(preceded(is_tag("-p"), alpha1), |value| {
            Result::String(value)
        }),
        map(
            preceded(is_tag("-p"), nom::combinator::verify(u8, |v| v != &0)),
            |value| Result::Int(value),
        ),
        nom::combinator::value(
            Result::String("ip"),
            preceded(is_tag("-p"), alt((tag("0"), tag("all")))),
        ),
    ))
    .parse(s)
}

fn protocol(s: &str) -> IResult<&str, Token> {
    let positive = map(protocol_value, |value| match value {
        Result::Int(value) => {
            Token::ProtocolNumber(d::IntOperator::new(d::OperatorType::EQ, vec![value]))
        }
        Result::String(value) => {
            Token::Protocol(d::StringOperator::new(d::OperatorType::EQ, vec![value]))
        }
    });

    let negative = map(protocol_value, |value| match value {
        Result::Int(value) => {
            Token::ProtocolNumber(d::IntOperator::new(d::OperatorType::NEQ, vec![value]))
        }
        Result::String(value) => {
            Token::Protocol(d::StringOperator::new(d::OperatorType::NEQ, vec![value]))
        }
    });

    preceded(space1, alt((positive, preceded(tag("! "), negative))))(s)
}

enum Token<'a> {
    Jump(&'a str),
    RejectWith(&'a str),
    Goto(d::ActionSetting<'a>),
    Name(&'a str),
    Protocol(d::StringOperator<'a>),
    ProtocolNumber(d::IntOperator),
    Error(&'a str),
    ActionModifier(d::ActionSetting<'a>),
}

struct Tokens<'a>(Vec<Token<'a>>);

impl<'a> Serialize for Tokens<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut number = 0;
        let mut action_modifier = 0;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;

        let mut iter = self.0.iter();
        while let Some(item) = iter.next() {
            match item {
                Token::Error(a) => {
                    map.serialize_entry(&format!("error_{}", number), &a)?;
                    number += 1;
                },
                Token::Goto(a) => map.serialize_entry("goto", &a)?,
                Token::Jump(a) => map.serialize_entry("jump", &a)?,
                Token::RejectWith(a) => map.serialize_entry("reject-with", &a)?,
                Token::ActionModifier(a) => {
                    map.serialize_entry(&format!("action_modifier_{}", action_modifier), &a)?;
                    action_modifier += 1;
                }
                Token::Name(a) => map.serialize_entry("name", &a)?,
                Token::Protocol(a) => map.serialize_entry("protocol", &a)?,
                Token::ProtocolNumber(a) => map.serialize_entry("protocol_number", &a)?,
            }
            
            
        }

        map.end()
    }
}

fn parser(input: &str) -> IResult<&str, Tokens> {
    map(
        many1(alt((
            map(value("-A"), |value| Token::Name(value)),
            map(rstrip_value("-j"), |value| Token::Jump(value)),
            map(rstrip_value("--reject-with"), |value| {
                Token::RejectWith(value)
            }),
            map(rstrip_value("-g"), |value| {
                Token::Goto(d::ActionSetting::new(d::ActionType::GOTO, value))
            }),
            map(rstrip_value("--log-level"), |value| {
                Token::ActionModifier(d::ActionSetting::new(d::ActionType::LogLevel, value))
            }),
            map(rstrip_value("--log-prefix"), |value| {
                Token::ActionModifier(d::ActionSetting::new(d::ActionType::LogPrefix, value))
            }),
            map(rstrip_tag("--log-tcp-sequence"), |_| {
                Token::ActionModifier(d::ActionSetting::new(d::ActionType::LogTCPSequence, ""))
            }),
            map(rstrip_tag("--log-tcp-options"), |_| {
                Token::ActionModifier(d::ActionSetting::new(d::ActionType::LogTCPOptions, ""))
            }),
            map(rstrip_tag("--log-ip-option"), |_| {
                Token::ActionModifier(d::ActionSetting::new(d::ActionType::LogIPOptions, ""))
            }),
            protocol,
            unknown_part,
        ))),
        |value| Tokens(value),
    )
    .parse(input)
}

struct ActionSettingBuilder<'a>(d::ActionSetting<'a>);
impl<'a> ActionSettingBuilder<'a> {
    pub fn new() -> Self {
        let default = d::ActionSetting::new(d::ActionType::PASS, "");
        Self(default)
    }
    fn goto(&mut self, action: d::ActionSetting<'a>) {
        self.0 = action
    }
    fn action(&mut self, action: &'a str) {
        if let Ok(action_type) = d::ActionType::from_str(action) {
            match action_type {
                d::ActionType::ACCEPT
                | d::ActionType::DROP
                | d::ActionType::QUEUE
                | d::ActionType::RETURN
                | d::ActionType::LOG => self.0 = d::ActionSetting::new(action_type, ""),
                d::ActionType::LogPrefix | d::ActionType::LogLevel | d::ActionType::REJECT => {
                    self.0.action = action_type
                }

                _ => !todo!(),
            }
        }
    }
    fn option(&mut self, option: &'a str) {
        self.0.option = option
    }
    fn jump(&mut self, action: &'a str, user_chains: &Vec<&'a str>) {
        user_chains
            .contains(&action)
            .then(|| self.0 = d::ActionSetting::new(d::ActionType::JUMP, action));
    }
    fn build(self) -> d::ActionSetting<'a> {
        self.0
    }
}

struct ACLRuleBuilder;
impl<'a> ACLRuleBuilder {
    fn new() -> Self {
        Self
    }
    fn build(
        &self,
        action: d::ActionSetting<'a>,
        normalized_action: Option<d::NormalizedAction>,
        action_modifiers:  Vec<d::ActionSetting<'a>>
    ) -> d::ACLRule<'a> {
        d::ACLRule::new(vec![action], vec![normalized_action], action_modifiers)
    }
}

struct RuleBuilder<'a> {
    action: ActionSettingBuilder<'a>,
    name: Option<&'a str>,
    action_modifiers: Vec<d::ActionSetting<'a>>

}
impl<'a> RuleBuilder<'a> {
    pub fn new() -> Self {
        Self {
            action: ActionSettingBuilder::new(),
            name: None,
            action_modifiers: vec![d::ActionSetting::new(domain::ActionType::LogLevel, "warning")]
        }
    }

    fn build(
        mut self,
        input: &'a str,
        user_chains: &Vec<&'a str>,
    ) -> IResult<&'a str, (&'a str, d::ACLRule<'a>)> {
        let (input, tokens) = parser(input)?;
        let mut iter = tokens.0.into_iter();

        while let Some(item) = iter.next() {
            match item {
                Token::Name(value) => self.name = Some(value),
                Token::Goto(value) => self.action.goto(value),
                Token::Jump(value) => {
                    self.action.action(value);
                    self.action.jump(value, user_chains)
                }
                Token::RejectWith(value) => self.action.option(value),
                Token::ActionModifier(value) => {
                    if value.action == d::ActionType::LogLevel {
                        self.action_modifiers[0] = value
                    } else {
                        self.action_modifiers.push(value)
                    }
                    
                }

                _ => (),
            }
        }
        let action = self.action.build();
        let normalized_action = action.normalized_action().ok();
        let mut action_modifiers = vec![];
        if action.action == d::ActionType::LOG {
            action_modifiers.extend(self.action_modifiers);
        }

        Ok((
            input,
            (
                self.name.unwrap_or_default(),
                ACLRuleBuilder::new().build(action, normalized_action, action_modifiers),
            ),
        ))
    }
}

pub fn rule<'a>(input: &'a str, user_chains: &Vec<&'a str>) -> IResult<&'a str, d::ACLRule<'a>> {
    let builder = RuleBuilder::new();

    let (remain, (_, rule)) = builder.build(input, user_chains)?;
    Ok((remain, rule))
}
