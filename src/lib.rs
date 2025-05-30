use nom::character::complete::not_line_ending;
use nom::multi::many1;
use nom::sequence::{preceded, tuple};
use nom::Parser;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::space1,
    combinator::{map, value},
    IResult,
};
use std::collections::HashMap;
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

    #[test]
    fn test_parser_new() {
        let (remaining, result) = parser(" -j REJECT").unwrap();
        assert_eq!(remaining, "");
        assert_eq!(result.first().unwrap().1.value().unwrap(), "REJECT");
    }

    #[test]
    fn test_serialize() {
        let arg = d::ActionType::ACCEPT;
        let r = toml::to_string(&arg).unwrap();
        println!("{}", r);
        assert_eq!(r, "")

    }



    #[tester("acl.toml")]
    fn test_rule(arg: &str) -> IResult<&str, d::ACLRule> {
        let v = vec![];
        rule(arg, &v)
    }


    #[tester("parser.toml")]
    fn test_parser(arg: &str) -> IResult<&str, Vec<(&str, Result)>> {
        parser(arg)

    }
}

fn name<'a>(input: &str) -> IResult<&str, &str> {
    preceded(tuple((tag("-A"), space1)), until_eof).parse(input)
}

fn tag_value(arg: &'static str) -> impl Fn(&str) -> IResult<&str, Result> {
    move |input: &str| {
        preceded(tuple((space1, tag(arg), space1)), until_eof)
            .map(|value| Result::Value(value))
            .parse(input)
    }
}

fn is_tag(arg: &'static str) -> impl Fn(&str) -> IResult<&str, Result> {
    move |input: &str| value(Result::Tag, preceded(space1, tag(arg))).parse(input)
}


#[derive(Clone, Serialize)]
enum Result<'a> {
    Value(&'a str),
    Tag,
}

impl<'a> Result<'a> {
    fn value(&self) -> Option<&'a str> {
        match self {
            Self::Value(value) => Some(value),
            _ => None,
        }
    }
}


fn parser(input: &str) -> IResult<&str, Vec<(&str, Result)>> {
    many1(alt((
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
        map(is_tag("--log-ip-option"), |value| ("log-ip-option", value)),
    )))
    .parse(input)
}

fn until_eof(s: &str) -> IResult<&str, &str> {
    let is_next = alt((take_until(" !"), take_until(" -")));

    alt((is_next, not_line_ending))(s)
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

pub fn rule<'a>(s: &'a str, user_chains: &Vec<&'a str>) -> IResult<&'a str, d::ACLRule<'a>> {
    let (input, name) = name(s)?;

    let (input, tokens) = parser(input)?;

    let mut builder = RuleBuilder::new(name);

    let map: HashMap<&str, Result> = tokens.into_iter().collect();

    builder.goto(map.get("goto").and_then(|value| value.value()));

    builder.action(map.get("jump").and_then(|value| value.value()));

    builder.jump(map.get("jump").and_then(|value| value.value()), user_chains);

    let rule = builder.build();

    Ok((input, rule))
}
