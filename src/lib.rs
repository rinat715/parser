use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::{not_line_ending, space1},
    combinator::{eof, map, value},
    multi::many1,
    sequence::{pair, preceded, tuple},
    IResult, Parser,
};
use serde::{Serialize, Serializer, ser::SerializeMap};
use std::str::{from_boxed_utf8_unchecked, FromStr};

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

fn first_tag_value(arg: &'static str) -> impl Fn(&str) -> IResult<&str, Token> {
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

fn unknown_part(input: &str) -> IResult<&str, Token> {
    preceded(space1, until_eof)
        .map(|value| Token::Value(value))
        .parse(input)
}

#[derive(Clone, Debug)]
enum Token<'a> {
    Value(&'a str),
    Errors(Vec<&'a str>),
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
            Token::Errors(ref v) => serializer.serialize_str(&v.join(" ")),
        }
    }
}


struct Tokens<'a>(Vec<(&'a str, Token<'a>)>);


impl<'a> Serialize for Tokens<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            map.serialize_entry(k, &v)?;
        }
        map.end()
    }
}



fn parser(input: &str) -> IResult<&str, Tokens> {
    map(many1(alt((
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
        map(is_tag("--log-ip-option"), |value| ("log-ip-option", value)),
        map(unknown_part, |value| ("error", value)),
    ))), |value| Tokens(value) )
    .parse(input)
}

struct RuleBuilder<'a>(d::ACLRule<'a>);
impl<'a> RuleBuilder<'a> {
    pub fn new() -> Self {
        let action = d::ActionSetting::new(domain::ActionType::PASS, "");
        let normalized_action = Option::None;
        Self(d::ACLRule::new(action, normalized_action, ""))
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
    fn parse(&mut self, tokens: &'a Tokens, user_chains: &Vec<&'a str>) -> &Tokens {
        let mut iter = tokens.0.iter();

        while let Some(item) = iter.next() {
            match item.0 {
                "name" => self.0.name = item.1.value().u,
                "goto" => self.goto(item.1.value()),
                "jump" => {
                    self.action(item.1.value());
                    self.jump(item.1.value(), user_chains)
                }

                _ => !todo!()
            }
        }
        tokens
    }
    fn build(mut self) -> d::ACLRule<'a> {
        self.normalized_action();
        self.0
    }
}

pub fn rule<'a>(input: &'a str, user_chains: &Vec<&'a str>) -> IResult<&'a str, d::ACLRule<'a>> {
    let (input, tokens) = parser(input)?;

    let mut builder = RuleBuilder::new();
    let _ = builder.parse(&tokens, user_chains);

    let rule = builder.build();

    Ok((input, rule))
}
