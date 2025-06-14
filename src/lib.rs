use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::{alpha1, not_line_ending, space1, u16},
    combinator::{map, success, verify, opt},
    multi::{many1, separated_list1},
    sequence::{pair, preceded, separated_pair, terminated, tuple},
    IResult, Parser,
};
use serde::{ser::SerializeMap, Serialize, Serializer};
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

    #[test]
    fn test_flag() {
        assert_eq!(flag("SYN").unwrap(), ("", "SYN"));
        assert_eq!(flags("SYN").unwrap(), ("", vec!["SYN"]));
        assert_eq!(flags("FIN,SYN,ACK").unwrap(), ("", vec!["FIN","SYN","ACK"]))
    }
}

fn until_eof(s: &str) -> IResult<&str, &str> {
    let is_next = alt((take_until(" !"), take_until(" -")));

    alt((is_next, not_line_ending))(s)
}

fn name(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded(tuple((tag(arg), space1)), until_eof).parse(input)
}

fn strip_value(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded(strip_tag(arg), until_eof).parse(input)
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

// struct Negative(bool);
// impl Negative {
//     fn () {
        
//     }
// }

fn is_neg(s: &str) -> IResult<&str, bool> { // TODO option
    map(opt(rstrip_tag("!")), |value| value.is_some()).parse(s)
}


enum Int {
    Single(u16),
    Range(u16, u16)
}

fn int(s: &str) -> IResult<&str, Int> {
    alt((
        map(u16::<_, nom::error::Error<&str>>, |value| Int::Single(value)),
        map(separated_pair(u16, tag(":"), u16), |(f, s)| Int::Range(f, s)),
    ))
    .parse(s)
}

fn int_operator(is_neg: bool, value: Int) -> d::IntOperator {
    match value {
        Int::Single(value) => d::IntOperator::new(is_neg.then(||d::OperatorType::NEQ), values)
        
    }
}

//  IntOperator --sport 500:600 --dport 45
fn port(arg: &'static str) -> impl Fn(&str) -> IResult<&str, d::IntOperator> {
    move |input: &str| {
        map(
            pair(operator, preceded(strip_tag(arg), int)),
            |(operator, value)| d::IntOperator::new(operator, value),
        )
        .parse(input)
    }
}

// ! --ports 50,300:400
// --ports 50
fn ports(arg: &'static str) -> impl Fn(&str) -> IResult<&str, Vec<d::IntOperator>> {
    move |input: &str| {
        alt((
            map(
                pair(
                    operator,
                    preceded(strip_tag(arg), separated_list1(tag(","), int)),
                ),
                |(operator, value)| {
                    value
                        .into_iter()
                        .map(|i| d::IntOperator::new(operator.clone(), i))
                        .collect()
                },
            ),
            map(port(arg), |value| vec![value]),
        ))
        .parse(input)
    }
}

// --tcp-flags

static TCP_FLAGS: [&'static str; 8] = ["SYN", "ACK", "FIN", "RST", "URG", "PSH", "ALL", "NONE"];
static TCP_FLAGS_ALL: [&'static str; 6] = ["SYN", "ACK", "FIN", "RST", "URG", "PSH"];

fn flag(s: &str) -> IResult<&str, &str> {
    verify(alpha1, |value| TCP_FLAGS.contains(value)).parse(s)
}

fn flags(s: &str) -> IResult<&str, Vec<&str>> {
    alt((
        separated_list1(tag(","), flag),
        map(flag, |value| vec![value]),
    )).parse(s)
}
//  --tcp-flags FIN,SYN,ACK ACK
// ! --tcp-flags FIN,SYN,ACK ACK
fn tcp_flag(s: &str) -> IResult<&str, (d::StringOperator, d::StringOperator)> {
    map(
        pair(
            operator,
            preceded(
                strip_tag("--tcp-flags"),
                separated_pair(flags, space1, flags)
            ),
        ),
        |(operator, value)| {
            if operator == d::OperatorType::EQ {
                let second = d::StringOperator::new(d::OperatorType::NEQ, value.0.into_iter().filter(|x| !value.1.contains(x) ).collect());
                let first = d::StringOperator::new(d::OperatorType::EQ, value.1);
                return (first, second)
            }
            else {
                !todo!("not realize neg")
            }
        },
    )
    .parse(s)
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
    ActionSetting(ActionSetting<'a>),
    Option(&'a str),
    Name(&'a str),
    Protocol(d::StringOperator<'a>),
    ProtocolNumber(d::IntOperator),
    SourcePorts(Vec<d::IntOperator>),
    DestinationPorts(Vec<d::IntOperator>),
    Ports(Vec<d::IntOperator>),
    Error(&'a str),
    ActionModifier(d::ActionSetting<'a>), // TODO  переписать на ActionSetting
    TCPFlags((d::StringOperator<'a>,  d::StringOperator<'a>)),
}

struct ActionModifiers<'a>(Vec<d::ActionSetting<'a>>);
impl<'a> ActionModifiers<'a> {
    fn add(&mut self, item: d::ActionSetting<'a>) {
        // TODO  переписать на ActionSetting
        if item.is_type(d::ActionType::LogLevel) {
            self.0[0] = item
        } else {
            self.0.push(item)
        }
    }
    fn build(self) -> Vec<d::ActionSetting<'a>> {
        self.0
    }
}

impl<'a> Default for ActionModifiers<'a> {
    fn default() -> Self {
        Self(vec![d::ActionSetting::new(
            d::ActionType::LogLevel,
            "warning",
        )])
    }
}

struct Tokens<'a>(Vec<Token<'a>>);

impl<'a> Tokens<'a> {
    fn build(self) -> (&'a str, d::ACLRule<'a>) {
        let mut action: ActionSetting = Default::default();
        let mut action_modifiers: ActionModifiers = Default::default();

        let mut name = "";

        self.0.into_iter().for_each(|i| {
            match i {
                Token::Name(value) => name = value,
                Token::ActionSetting(value) => action = value,
                Token::Action(value) => action.action(value),
                Token::Option(value) => action.option(value),
                Token::ActionModifier(value) => action_modifiers.add(value),
                Token::Protocol(value) => todo!(),
                Token::ProtocolNumber(value) => todo!(),
                Token::DestinationPorts(value) => todo!(),
                Token::SourcePorts(value) => todo!(),
                Token::Ports(value) => todo!(),
                Token::TCPFlags(value) => todo!(),
                Token::Error(_) => (), // _ => println!(),
            }
        });

        let mut rule: ACLRule = Default::default();

        rule.action(action, action_modifiers);

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
                Token::TCPFlags(a) => map.serialize_entry("tcp-flags", &a)?,
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
            map(name("-A"), |value| Token::Name(value)),
            map(verify(strip_value("-j"), is_user_chain), |value| {
                Token::ActionSetting(ActionSetting::new(d::ActionType::JUMP, Some(value)))
            }),
            map(
                verify(strip_value("-j"), |value| {
                    d::ActionType::from_str(value).is_ok()
                }),
                |value| Token::Action(d::ActionType::from_str(value).unwrap()),
            ),
            map(strip_value("--reject-with"), |value| Token::Option(value)),
            map(strip_value("-g"), |value| {
                Token::ActionSetting(ActionSetting::new(d::ActionType::GOTO, Some(value)))
            }),
            map(strip_value("--log-level"), |value| {
                Token::ActionModifier(d::ActionSetting::new(d::ActionType::LogLevel, value))
            }),
            map(strip_value("--log-prefix"), |value| {
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
            map(tcp_flag, |value| Token::TCPFlags(value)),
            unknown_part,
        ))),
        |value| Tokens(value),
    )
    .parse(input)
}

#[derive(Serialize)]
struct ActionSetting<'a> {
    action: d::ActionType,
    option: Option<&'a str>,
} // TODO derive_builder
impl<'a> ActionSetting<'a> {
    fn new(action: d::ActionType, option: Option<&'a str>) -> Self {
        Self {
            action: action,
            option: option,
        }
    }

    fn action(&mut self, action: d::ActionType) {
        self.action = action;
    }

    fn option(&mut self, option: &'a str) {
        self.option = Some(option);
    }

    fn build(self) -> d::ActionSetting<'a> {
        d::ActionSetting::new(self.action, self.option.unwrap_or(""))
    }
}

impl<'a> Default for ActionSetting<'a> {
    fn default() -> Self {
        Self {
            action: d::ActionType::PASS,
            option: None,
        }
    }
}

#[derive(Serialize)]
struct ACLRule<'a> {
    action_modifiers: Vec<d::ActionSetting<'a>>,
    action: Option<d::ActionSetting<'a>>,
    normalized_action: Option<d::NormalizedAction>,
} // TODO derive_builder
impl<'a> ACLRule<'a> {
    fn action(&mut self, action_bulder: ActionSetting<'a>, modifiers: ActionModifiers<'a>) {
        let action = action_bulder.build();
        action
            .is_type(d::ActionType::LOG)
            .then(|| self.action_modifiers = modifiers.build());
        self.normalized_action = action.normalized_action().ok();
        self.action = Some(action);
    }

    fn build(self) -> d::ACLRule<'a> {
        d::ACLRule::new(
            vec![self.action.unwrap()],
            vec![self.normalized_action],
            self.action_modifiers,
        )
    }
}

impl<'a> Default for ACLRule<'a> {
    fn default() -> Self {
        Self {
            action_modifiers: vec![],
            action: None,
            normalized_action: None,
        }
    }
}

pub fn rule<'a>(input: &'a str, user_chains: &Vec<&'a str>) -> IResult<&'a str, d::ACLRule<'a>> {
    let (remain, (name, rule)) = parser(input, |v| user_chains.contains(&v))
        .map(|(remain, tokens)| (remain, tokens.build()))?;

    Ok((remain, rule))
}
