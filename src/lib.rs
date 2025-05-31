use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::{not_line_ending, space1},
    combinator::{map, value},
    multi::many1,
    sequence::{preceded, tuple, pair},
    IResult, Parser,
};
use serde::{Serialize, Serializer};
use std::collections::HashMap;
use std::str::FromStr;

mod domain;
use domain as d;

#[derive(Debug, PartialEq, Eq)]
pub struct ParseEnum2Error; // TODO нормальное название

#[cfg(test)]
mod tests {
    use super::*;
    use tester::tester;

    #[test]
    fn test_parser_new() {
        let (remaining, result) = parser(" -j REJECT").unwrap();
        assert_eq!(remaining, "");
        assert_eq!(
            result.get("jump").and_then(|value| value.value()),
            Some("REJECT")
        )
    }

    #[tester("acl.toml")]
    fn test_rule(arg: &str) -> IResult<&str, d::ACLRule> {
        let v = vec![];
        rule(arg, &v)
    }

    #[tester("parser.toml")]
    fn test_parser(arg: &str) -> IResult<&str, HashMap<&str, Token>> {
        parser(arg)
    }
}

fn until_eof(s: &str) -> IResult<&str, &str> {
    let is_next = alt((take_until(" !"), take_until(" -")));

    alt((is_next, not_line_ending))(s)
}

fn first_tag_value(arg: &'static str) -> impl Fn(&str) -> IResult<&str, Token>  {
    move |input: &str| {
        preceded(tuple((tag(arg), space1)), until_eof)
            .map(|value| Token::Value(value))
            .parse(input)
    }
}

fn tag_value(arg: &'static str) -> impl Fn(&str) -> IResult<&str, Token> {
    move |input: &str| {
        preceded(pair(space1, tuple((tag(arg), space1))), until_eof)
            .map(|value| Token::Value(value))
            .parse(input)
    }
}

fn is_tag(arg: &'static str) -> impl Fn(&str) -> IResult<&str, Token> {
    move |input: &str| value(Token::Tag, preceded(space1, tag(arg))).parse(input)
}

#[derive(Clone)]
enum Token<'a> {
    Value(&'a str),
    Tag,
}

impl<'a> Token<'a> {
    fn value(&self) -> Option<&'a str> {
        match self {
            Self::Value(value) => Some(value),
            _ => None,
        }
    }
}

impl<'a> Serialize for Token<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            Token::Value(a) => serializer.serialize_str(a),
            Token::Tag => serializer.serialize_str("tag"),
        }
    }
}

fn parser(input: &str) -> IResult<&str, HashMap<&str, Token>> {
    map(
        many1(alt((
            map(first_tag_value("-A"), |value| ("name", value)),
            map(tag_value("-j"), |value| ("jump", value)),
            map(tag_value("-g"), |value| ("goto", value)),
            map(tag_value("--log-level"), |value| ("log_level", value)),
            map(tag_value("--log-prefix"), |value| ("log-prefix", value)),
            map(is_tag("--log-tcp-sequence"), |value| {
                ("log-tcp-sequence", value)
            }),
            map(is_tag("--log-tcp-options"), |value| {
                ("log-tcp-options", value)
            }),
            map(is_tag("--log-ip-option"), |value| ("log-ip-option", value)), // TODO s
        ))),
        |value| value.into_iter().collect(),
    )
    .parse(input)
}

struct RuleBuilder<'a>(d::ACLRule<'a>);
impl<'a> RuleBuilder<'a> {
    pub fn new(name: &'a str) -> Self {
        let action = d::ActionSetting::new(domain::ActionType::PASS, "");
        let normalized_action = Option::None;
        Self(d::ACLRule::new(action, normalized_action, name))
    }

    fn goto(&mut self, action: Option<&'a str>) {
        action.map(|value| self.0.action = vec![d::ActionSetting::new(d::ActionType::GOTO, value)]);
    }
    fn action(&mut self, action: Option<&'a str>) {
        action.map(|value| {
            d::ActionType::from_str(value)
                .map(|value| d::ActionSetting::new(value, ""))
                .map(|value| self.0.action = vec![value])
        });
    }
    fn jump(&mut self, action: Option<&'a str>, user_chains: &Vec<&'a str>) {
        action.map(|value| {
            user_chains.contains(&value).then_some(|value| {
                self.0.action = vec![d::ActionSetting::new(d::ActionType::JUMP, value)]
            })
        });
    }
    fn normalized_action(&mut self) {
        self.0.normalized_action = vec![self
            .0
            .action
            .first()
            .and_then(|value| value.normalized_action().ok())];
    }
    fn build(mut self) -> d::ACLRule<'a> {
        self.normalized_action();
        self.0
    }
}

pub fn rule<'a>(input: &'a str, user_chains: &Vec<&'a str>) -> IResult<&'a str, d::ACLRule<'a>> {
    let (input, tokens) = parser(input)?;

    let mut builder = RuleBuilder::new(tokens.get("name").and_then(|value| value.value()).unwrap());


    builder.goto(tokens.get("goto").and_then(|value| value.value()));

    builder.action(tokens.get("jump").and_then(|value| value.value()));

    builder.jump(tokens.get("jump").and_then(|value| value.value()), user_chains);

    let rule = builder.build();

    Ok((input, rule))
}
