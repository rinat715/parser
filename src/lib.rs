use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::{alpha1, not_line_ending, space1, u16},
    combinator::{map, success, verify},
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
        parser(arg, |_| false)
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
    Action(d::ActionType),
    ActionSetting(d::ActionSetting<'a>),
    Option(&'a str),
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

impl<'a> Tokens<'a> {
    fn build(self) -> (&'a str, d::ACLRule<'a>) {
        let mut action: ActionSetting = Default::default();
        let mut action_modifiers = vec![d::ActionSetting::new(d::ActionType::LogLevel, "warning")];

        let mut name = "";

        self.0.into_iter().for_each(|i| {
            match i {
                Token::Name(value) => name = value,
                Token::ActionSetting(value) => action.0 = value,
                Token::Action(value) => action.0.action = value,
                Token::Option(value) => action.0.option = value,
                Token::ActionModifier(value) => {
                    if value.action == d::ActionType::LogLevel {
                        action_modifiers[0] = value
                    } else {
                        action_modifiers.push(value)
                    }
                }
                Token::Protocol(value) => todo!(),
                Token::ProtocolNumber(value) => todo!(),
                Token::DestinationPorts(value) => todo!(),
                Token::SourcePorts(value) => todo!(),
                Token::Ports(value) => todo!(),
                Token::Error(_) => (), // _ => println!(),
            }
        });

        let mut rule: ACLRule = Default::default();

        rule.action(action.build(), action_modifiers);

        (name, rule.build())
    }
}

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
                Token::ActionSetting(a) => map.serialize_entry("action_settings", &a)?,
                Token::Action(a) => map.serialize_entry("action", a)?,
                Token::Option(a) => map.serialize_entry("option", &a)?,
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

fn parser<F>(input: &str, is_user_chain: F) -> IResult<&str, Tokens>
where
    F: Fn(&str) -> bool,
{
    map(
        many1(alt((
            map(value("-A"), |value| Token::Name(value)),
            map(verify(rstrip_value("-j"), is_user_chain), |value| {
                Token::ActionSetting(d::ActionSetting::new(d::ActionType::JUMP, value))
            }),
            map(
                verify(rstrip_value("-j"), |value| {
                    d::ActionType::from_str(value).is_ok()
                }),
                |value| Token::Action(d::ActionType::from_str(value).unwrap()),
            ),
            map(rstrip_value("--reject-with"), |value| Token::Option(value)),
            map(rstrip_value("-g"), |value| {
                Token::ActionSetting(d::ActionSetting::new(d::ActionType::GOTO, value))
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

struct ActionSetting<'a>(d::ActionSetting<'a>);
impl<'a> ActionSetting<'a> {
    fn build(self) -> d::ActionSetting<'a> {
        self.0
    }
}

impl<'a> Default for ActionSetting<'a> {
    fn default() -> Self {
        Self(d::ActionSetting::new(d::ActionType::PASS, ""))
    }
}

struct ACLRule<'a>(d::ACLRule<'a>);
impl<'a> ACLRule<'a> {
    fn action(&mut self, action: d::ActionSetting<'a>, modifiers: Vec<d::ActionSetting<'a>>) {
        let normalized_action = action.normalized_action().ok();
        if action.action == d::ActionType::LOG {
            self.0.action_modifiers = modifiers
        }
        self.0.action.push(action);
        self.0.normalized_action.push(normalized_action);
    }

    fn build(self) -> d::ACLRule<'a> {
        self.0
    }
}

impl<'a> Default for ACLRule<'a> {
    fn default() -> Self {
        Self(d::ACLRule::new(vec![], vec![], vec![]))
    }
}

pub fn rule<'a>(input: &'a str, user_chains: &Vec<&'a str>) -> IResult<&'a str, d::ACLRule<'a>> {
    let (remain, (name, rule)) = parser(input, |v| user_chains.contains(&v))
        .map(|(remain, tokens)| (remain, tokens.build()))?;

    Ok((remain, rule))
}
