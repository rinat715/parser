use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::{not_line_ending, space1},
    combinator::map,
    multi::many1,
    sequence::{pair, preceded, tuple},
    IResult, Parser,
};
use serde::{de::value, ser::SerializeMap, Serialize, Serializer};
use std::str::FromStr;

mod domain;
use domain as d;

#[derive(Debug, PartialEq, Eq)]
pub struct ParseEnum2Error; // TODO нормальное название

#[cfg(test)]
mod tests {
    use super::*;
    use tester::tester;

    // #[test]
    // fn test_parser_new() {
    //     let (remaining, result) = parser(" -j REJECT").unwrap();
    //     assert_eq!(remaining, "");
    //     match result.0.first().unwrap()  {

    //     }
    //     assert_eq!(result.0.first().unwrap(), Token::Jump("REJECT"))
    // }

    #[tester("acl.toml")]
    fn test_rule(arg: &str) -> IResult<&str, d::ACLRule> {
        let v = vec![];
        rule(arg, &v)
    }

    #[tester("parser.toml")]
    fn test_parser(arg: &str) -> IResult<&str, Tokens> {
        parser(arg)
    }
}

fn until_eof(s: &str) -> IResult<&str, &str> {
    let is_next = alt((take_until(" !"), take_until(" -")));

    alt((is_next, not_line_ending))(s)
}

fn first_tag_value(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded(tuple((tag(arg), space1)), until_eof).parse(input)
}

fn tag_value(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded(pair(space1, tuple((tag(arg), space1))), until_eof).parse(input)
}

fn is_tag(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded(space1, tag(arg)).parse(input)
}

fn unknown_part(input: &str) -> IResult<&str, Token> {
    preceded(space1, until_eof)
        .map(|value| Token::Error(value))
        .parse(input)
}

#[derive(Clone, Debug)]
enum Token<'a> {
    Jump(&'a str),
    Goto(&'a str),
    Name(&'a str),
    Error(&'a str),
    LogLevel(&'a str),
    LogPrefix(&'a str),
    LogTcpSequence,
    LogTcpOptions,
    LogIpOption,
}

impl<'a> Serialize for Token<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            Token::Error(a)
            | Token::Goto(a)
            | Token::Name(a)
            | Token::LogLevel(a)
            | Token::LogPrefix(a)
            | Token::Jump(a) => serializer.serialize_str(a),
            Token::LogTcpOptions | Token::LogTcpSequence | Token::LogIpOption => {
                serializer.serialize_str("tag")
            }
        }
    }
}

struct Tokens<'a>(Vec<Token<'a>>);

impl<'a> Serialize for Tokens<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut errors: Vec<&str> = vec![];
        let mut map = serializer.serialize_map(Some(self.0.len()))?;

        let mut iter = self.0.iter();
        while let Some(item) = iter.next() {
            match item {
                Token::Error(a) => errors.push(a),
                Token::Goto(a) => map.serialize_entry("goto", &a)?,
                Token::Jump(a) => map.serialize_entry("jump", &a)?,
                Token::LogIpOption => map.serialize_entry("log-ip-option", "tag")?,
                Token::LogLevel(a) => map.serialize_entry("log-level", &a)?,
                Token::LogPrefix(a) => map.serialize_entry("log-prefix", &a)?,
                Token::LogTcpOptions => map.serialize_entry("log-tcp-options", "tag")?,
                Token::LogTcpSequence => map.serialize_entry("log-tcp-sequence", "tag")?,
                Token::Name(a) => map.serialize_entry("name", &a)?,
            }
        }
        if !errors.is_empty() {
            let errors_str = errors.join(" ");
            map.serialize_entry("errors", &errors_str)?;
        }

        map.end()
    }
}

fn parser(input: &str) -> IResult<&str, Tokens> {
    map(
        many1(alt((
            map(first_tag_value("-A"), |value| Token::Name(value)),
            map(tag_value("-j"), |value| Token::Jump(value)),
            map(tag_value("-g"), |value| Token::Goto(value)),
            map(tag_value("--log-level"), |value| Token::LogLevel(value)),
            map(tag_value("--log-prefix"), |value| Token::LogPrefix(value)),
            map(is_tag("--log-tcp-sequence"), |_| Token::LogTcpSequence),
            map(is_tag("--log-tcp-options"), |_| Token::LogTcpOptions),
            map(is_tag("--log-ip-option"), |_| Token::LogIpOption),
            unknown_part,
        ))),
        |value| Tokens(value),
    )
    .parse(input)
}

struct RuleBuilder<'a>(d::ACLRule<'a>);
impl<'a> RuleBuilder<'a> {
    pub fn new() -> Self {
        let action = d::ActionSetting::new(domain::ActionType::PASS, "");
        let normalized_action = Option::None;
        Self(d::ACLRule::new(action, normalized_action, ""))
    }

    fn goto(&mut self, action: &'a str) {
        self.0.action = vec![d::ActionSetting::new(d::ActionType::GOTO, action)];
    }
    fn action(&mut self, action: &'a str) {
        let _ = d::ActionType::from_str(action)
            .map(|value| d::ActionSetting::new(value, ""))
            .map(|value| self.0.action = vec![value]);
    }
    fn jump(&mut self, action: &'a str, user_chains: &Vec<&'a str>) {
        user_chains.contains(&action).then_some(|value| {
            self.0.action = vec![d::ActionSetting::new(d::ActionType::JUMP, value)]
        });
    }
    fn normalized_action(&mut self) {
        self.0.normalized_action = vec![self
            .0
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
        let mut iter = tokens.0.iter();

        while let Some(item) = iter.next() {
            match item {
                Token::Name(value) => self.0.name = value,
                Token::Goto(value) => self.goto(value),
                Token::Jump(value) => {
                    self.action(value);
                    self.jump(value, user_chains)
                }

                _ => (),
            }
        }

        self.normalized_action();
        Ok((input, self.0))
    }
}

pub fn rule<'a>(input: &'a str, user_chains: &Vec<&'a str>) -> IResult<&'a str, d::ACLRule<'a>> {
    let builder = RuleBuilder::new();

    builder.build(input, user_chains)
}
