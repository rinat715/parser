use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::{alpha1, not_line_ending, space1, u8},
    combinator::map,
    multi::many1,
    sequence::{pair, preceded, tuple},
    IResult, Parser,
};
use serde::{de::value, ser::SerializeMap, Serialize, Serializer};
use serde_derive::Serialize;
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
        let v = vec![];
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
    Goto(d::ActionSetting<'a>),
    Name(&'a str),
    Protocol(d::StringOperator<'a>),
    ProtocolNumber(d::IntOperator),
    Error(&'a str),
    LogLevel(&'a str),
    LogPrefix(&'a str),
    LogTcpSequence,
    LogTcpOptions,
    LogIpOption,
}

struct Tokens<'a>(Vec<Token<'a>>);

impl<'a> Serialize for Tokens<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut number = 0;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;

        let mut iter = self.0.iter();
        while let Some(item) = iter.next() {
            match item {
                Token::Error(a) => map.serialize_entry(&format!("error_{}", number), &a)?,
                Token::Goto(a) => map.serialize_entry("goto", &a)?,
                Token::Jump(a) => map.serialize_entry("jump", &a)?,
                Token::LogIpOption => map.serialize_entry("log-ip-option", "tag")?,
                Token::LogLevel(a) => map.serialize_entry("log-level", &a)?,
                Token::LogPrefix(a) => map.serialize_entry("log-prefix", &a)?,
                Token::LogTcpOptions => map.serialize_entry("log-tcp-options", "tag")?,
                Token::LogTcpSequence => map.serialize_entry("log-tcp-sequence", "tag")?,
                Token::Name(a) => map.serialize_entry("name", &a)?,
                Token::Protocol(a) => map.serialize_entry("protocol", &a)?,
                Token::ProtocolNumber(a) => map.serialize_entry("protocol_number", &a)?,
            }
            number += 1;
        }

        map.end()
    }
}

fn parser(input: &str) -> IResult<&str, Tokens> {
    map(
        many1(alt((
            map(value("-A"), |value| Token::Name(value)),
            map(rstrip_value("-j"), |value| Token::Jump(value)),
            map(rstrip_value("-g"), |value| Token::Goto(d::ActionSetting::new(d::ActionType::GOTO, value))),
            map(rstrip_value("--log-level"), |value| Token::LogLevel(value)),
            map(rstrip_value("--log-prefix"), |value| {
                Token::LogPrefix(value)
            }),
            map(rstrip_tag("--log-tcp-sequence"), |_| Token::LogTcpSequence),
            map(rstrip_tag("--log-tcp-options"), |_| Token::LogTcpOptions),
            map(rstrip_tag("--log-ip-option"), |_| Token::LogIpOption),
            protocol,
            unknown_part,
        ))),
        |value| Tokens(value),
    )
    .parse(input)
}

struct RuleBuilder<'a>{
    rule: d::ACLRule<'a>,
    action: Option<d::ActionType>,
    option: Option<&'a str>
}
impl<'a> RuleBuilder<'a> {
    pub fn new() -> Self {
        let action = d::ActionSetting::new(domain::ActionType::PASS, "");
        let normalized_action = Option::None;
        Self{rule: d::ACLRule::new(action, normalized_action, ""), action: Option::None, option: Option::None}
    }

    fn action(&mut self, action: &'a str) {
        let _ = d::ActionType::from_str(action)
            .map(|value| d::ActionSetting::new(value, ""))
            .map(|value| self.rule.action = vec![value]);
    }
    fn jump(&mut self, action: &'a str, user_chains: &Vec<&'a str>) {
        user_chains.contains(&action).then_some(|value| {
            self.rule.action = vec![d::ActionSetting::new(d::ActionType::JUMP, value)]
        });
    }
    fn normalized_action(&mut self) {
        self.rule.normalized_action = vec![self
            .rule
            .action
            .first()
            .and_then(|value| value.normalized_action().ok())];
    }

    fn build(
        mut self,
        input: &'a str,
        user_chains: &Vec<&'a str>,
    ) -> IResult<&'a str, d::ACLRule<'a>> {
        let (input, tokens) = parser(input)?;
        let mut iter = tokens.0.into_iter();

        while let Some(item) = iter.next() {
            match item {
                Token::Name(value) => self.rule.name = value,
                Token::Goto(value) => self.rule.action = vec![value],
                Token::Jump(value) => {
                    self.action(value);
                    self.jump(value, user_chains)
                }

                _ => (),
            }
        }

        self.normalized_action();
        Ok((input, self.rule))
    }
}

pub fn rule<'a>(input: &'a str, user_chains: &Vec<&'a str>) -> IResult<&'a str, d::ACLRule<'a>> {
    let builder = RuleBuilder::new();

    builder.build(input, user_chains)
}
