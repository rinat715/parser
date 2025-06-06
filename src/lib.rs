use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::{alpha1, not_line_ending, space1, u16},
    combinator::{map, map_parser, success, verify},
    multi::{many1, separated_list1},
    sequence::{pair, preceded, separated_pair, terminated, tuple},
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

fn value(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded(tuple((tag(arg), space1)), until_eof).parse(input)
}

fn rstrip_value(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded(space1, value(arg)).parse(input)
}

fn rstrip_tag(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded(space1, tag(arg)).parse(input)
}

fn strip_tag(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded(space1, terminated(tag(arg), space1)).parse(input)
}

fn unknown_part(input: &str) -> IResult<&str, Token> {
    preceded(space1, until_eof)
        .map(|value| Token::Error(value))
        .parse(input)
}

fn operator(s: &str) -> IResult<&str, d::OperatorType> {
    alt((
        nom::combinator::value(d::OperatorType::NEQ, rstrip_tag("!")),
        success(d::OperatorType::EQ),
    ))
    .parse(s)
}

fn int_or_range_int(s: &str) -> IResult<&str, Vec<u16>> {
    alt((
        map(u16::<_, nom::error::Error<&str>>, |value| vec![value]),
        map(separated_pair(u16, tag(":"), u16), |(f, s)| vec![f, s]),
    ))
    .parse(s)
}

//  IntOperator --sport 500:600 --dport 45
fn port(arg: &'static str) -> impl Fn(&str) -> IResult<&str, d::IntOperator> {
    move |input: &str| {
        map(
            pair(operator, preceded(strip_tag(arg), int_or_range_int)),
            |(operator, value)| d::IntOperator::new(operator, value),
        )
        .parse(input)
    }
}

// ! --ports 50,300:400
fn ports(arg: &'static str) -> impl Fn(&str) -> IResult<&str, Vec<d::IntOperator>> {
    move |input: &str| {
        map(
            pair(
                operator,
                preceded(strip_tag(arg), separated_list1(tag(","), int_or_range_int)),
            ),
            |(operator, value)| {
                value
                    .into_iter()
                    .map(|i| d::IntOperator::new(operator.clone(), i))
                    .collect()
            },
        )
        .parse(input)
    }
}

fn protocol(s: &str) -> IResult<&str, Token> {
    let string = alt((
        nom::combinator::value("ip", preceded(strip_tag("-p"), alt((tag("0"), tag("all"))))),
        preceded(strip_tag("-p"), alpha1),
    ));

    alt((
        map(
            pair(
                operator,
                preceded(strip_tag("-p"), verify(u16, |value| *value != 0)),
            ),
            |(operator, value)| Token::ProtocolNumber(d::IntOperator::new(operator, vec![value])),
        ),
        map(pair(operator, string), |(operator, value)| {
            Token::Protocol(d::StringOperator::new(operator, vec![value]))
        }),
    ))
    .parse(s)
}

enum Token<'a> {
    Jump(&'a str),
    RejectWith(&'a str),
    Goto(d::ActionSetting<'a>),
    Name(&'a str),
    Protocol(d::StringOperator<'a>),
    ProtocolNumber(d::IntOperator),
    SourcePorts(Vec<d::IntOperator>),
    DestinationPorts(Vec<d::IntOperator>),
    Ports(Vec<d::IntOperator>),
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
                }
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
                Token::Ports(a) => map.serialize_entry("ports", &a)?,
                Token::SourcePorts(a) => map.serialize_entry("sports", &a)?,
                Token::DestinationPorts(a) => map.serialize_entry("dports", &a)?,
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
            map(rstrip_tag("--log-ip-options"), |_| {
                Token::ActionModifier(d::ActionSetting::new(d::ActionType::LogIPOptions, ""))
            }),
            map(ports("--ports"), |value| Token::Ports(value)),
            map(
                alt((ports("--sports"), map(port("--sport"), |value| vec![value]))),
                |value| Token::SourcePorts(value),
            ),
            map(
                alt((ports("--dports"), map(port("--dport"), |value| vec![value]))),
                |value| Token::DestinationPorts(value),
            ),
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
        action_modifiers: Vec<d::ActionSetting<'a>>,
    ) -> d::ACLRule<'a> {
        d::ACLRule::new(vec![action], vec![normalized_action], action_modifiers)
    }
}

struct RuleBuilder<'a> {
    action: ActionSettingBuilder<'a>,
    name: Option<&'a str>,
    action_modifiers: Vec<d::ActionSetting<'a>>,
}
impl<'a> RuleBuilder<'a> {
    pub fn new() -> Self {
        Self {
            action: ActionSettingBuilder::new(),
            name: None,
            action_modifiers: vec![d::ActionSetting::new(d::ActionType::LogLevel, "warning")],
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
                Token::Protocol(value) => todo!(),
                Token::ProtocolNumber(value) => todo!(),
                Token::DestinationPorts(value) => todo!(),
                Token::SourcePorts(value) => todo!(),
                Token::Ports(value) => todo!(),
                Token::Error(_) => (), // _ => println!(),
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
    let (remain, (_, rule)) = RuleBuilder::new().build(input, user_chains)?;

    Ok((remain, rule))
}
