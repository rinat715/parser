use nom::{
    branch::alt,
    bytes::complete::{tag, take, take_until},
    character::complete::{alpha1, not_line_ending, space1, u16},
    combinator::{map, map_parser, opt, peek, rest_len, value, verify, recognize, not, eof},
    multi::{many1, separated_list1},
    sequence::{pair, preceded, separated_pair, terminated, tuple},
    IResult, Parser,
};
use serde::{ser::SerializeMap, Serialize, Serializer};
use serde_derive::Serialize;
use std::cmp;
use std::str::FromStr;

use d::RangeIntOperator;
use d::SingleIntOperator;
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
    fn test_protocol(arg: &str) -> IResult<&str, d::StringOperator> {
        protocol(arg)
    }

    #[tester("protocol_number.toml")]
    fn test_protocol_number(arg: &str) -> IResult<&str, d::IntOperator> {
        protocol_number(arg)
    }

    #[test]
    fn test_flag() {
        assert_eq!(TCPFlagsParser::parse_item("SYN").unwrap(), ("", "SYN"));
        assert_eq!(TCPFlagsParser::flags("SYN").unwrap(), ("", vec!["SYN"]));
        assert_eq!(
            TCPFlagsParser::flags("FIN,SYN,ACK").unwrap(),
            ("", vec!["FIN", "SYN", "ACK"])
        )
    }

    #[test]
    fn test_until_eof() {
        let (remaining, result) = until_eof("").unwrap();
        assert_eq!(remaining, "");
        assert_eq!(result, "");

        let (remaining, result) =
            until_eof("-A INPUT -s 10.0.0.12/32 -j DROP ! --tcp-flags FIN,SYN,ACK ACK").unwrap();
        assert_eq!(
            remaining,
            " -s 10.0.0.12/32 -j DROP ! --tcp-flags FIN,SYN,ACK ACK"
        );
        assert_eq!(result, "-A INPUT");

        let (remaining, result) =
            until_eof("-A INPUT ! -s 10.0.0.12/32 -j DROP ! --tcp-flags FIN,SYN,ACK ACK").unwrap();
        assert_eq!(
            remaining,
            " ! -s 10.0.0.12/32 -j DROP ! --tcp-flags FIN,SYN,ACK ACK"
        );
        assert_eq!(result, "-A INPUT");

        let (remaining, result) = until_eof("-A\ndf").unwrap();
        assert_eq!(remaining, "\ndf");
        assert_eq!(result, "-A");
    }

    #[test]
    fn test_unknown_part() {
        let (remaining, result) = unknown_part(" ").unwrap();
        assert_eq!(remaining, "");
        assert_eq!(result, " ");

        // let (remaining, result) = unknown_part("").unwrap();
        // assert_eq!(remaining, "");
        // assert_eq!(result, "");

        let (remaining, result) = unknown_part(" --match-set BlockedHosts dst,dst -j DROP").unwrap();
        assert_eq!(remaining, " -j DROP");
        assert_eq!(result, " --match-set BlockedHosts dst,dst");

        let (remaining, result) = unknown_part(" --match-set BlockedHosts dst,dst").unwrap();
        assert_eq!(remaining, "");
        assert_eq!(result, " --match-set BlockedHosts dst,dst");
    }
}

fn until_eof(s: &str) -> IResult<&str, &str> {
    // тут лучше взять регулярку наверное

    let res1 = map_parser(
        peek(take_until::<&str, &str, nom::error::Error<&str>>(" !")), // peek клонирует s: &str
        rest_len, // обычный len  только обернутый в trait InputLength
    )
    .parse(s);
    let res2 = map_parser(
        peek(take_until::<&str, &str, nom::error::Error<&str>>(" -")), // внутри take_until std str.find обернутый в FindSubstring
        rest_len,
    )
    .parse(s);

    match (res1, res2) {
        (Ok((_, len1)), Ok((_, len2))) => take(cmp::min(len1, len2)).parse(s),
        (Ok((_, len1)), Err(_)) => take(len1).parse(s),
        (Err(_), Ok((_, len2))) => take(len2).parse(s),
        (Err(_), Err(_)) => not_line_ending.parse(s),
    }
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

fn unknown_part(input: &str) -> IResult<&str, &str> {
    not(eof).parse(input)?;
    recognize(pair(opt(alt((tag(" -"), tag(" !")))), until_eof)).parse(input)
}

#[derive(Serialize, Clone, PartialEq)]
struct Negative(bool);
impl Negative {
    fn parse(s: &str) -> IResult<&str, Self> {
        map(opt(rstrip_tag("!")), |value| Self(value.is_some())).parse(s)
    }
}

impl d::RangeIntOperator for Negative {
    fn range(&self) -> d::OperatorType {
        match self.0 {
            true => d::OperatorType::NotRange,
            false => d::OperatorType::RANGE,
        }
    }
}

impl d::SingleIntOperator for Negative {
    fn single(&self) -> d::OperatorType {
        match self.0 {
            true => d::OperatorType::NEQ,
            false => d::OperatorType::EQ,
        }
    }
}

fn single_operator(s: &str) -> IResult<&str, d::OperatorType> {
    map(Negative::parse, |value| value.single()).parse(s)
}

enum SingleOrRangeInt {
    Single(u16),
    Range(u16, u16),
}
impl SingleOrRangeInt {
    fn parse(sep: &'static str) -> impl Fn(&str) -> IResult<&str, Self> {
        move |input: &str| {
            alt((
                map(u16::<_, nom::error::Error<&str>>, |value| {
                    Self::Single(value)
                }),
                map(separated_pair(u16, tag(sep), u16), |(f, s)| {
                    Self::Range(f, s)
                }),
            ))
            .parse(input)
        }
    }
}

struct PortParser;

impl PortParser {
    fn build<O>(operator: O, value: SingleOrRangeInt) -> d::IntOperator
    where
        O: SingleIntOperator + RangeIntOperator,
    {
        match value {
            SingleOrRangeInt::Single(v) => d::IntOperator::new(operator.single(), vec![v]),
            SingleOrRangeInt::Range(f, s) => d::IntOperator::new(operator.range(), vec![f, s]),
        }
    }
    fn port(s: &str) -> IResult<&str, SingleOrRangeInt> {
        SingleOrRangeInt::parse(":").parse(s)
    }

    //  IntOperator --sport 500:600 --dport 45
    fn parse_single(arg: &'static str) -> impl Fn(&str) -> IResult<&str, d::IntOperator> {
        move |input: &str| {
            let value = preceded(strip_tag(arg), Self::port);
            let parser = pair(Negative::parse, value);

            map(parser, |(operator, value)| Self::build(operator, value)).parse(input)
        }
    }
    // ! --ports 50,300:400
    // --ports 50
    fn parse_vec(arg: &'static str) -> impl Fn(&str) -> IResult<&str, Vec<d::IntOperator>> {
        move |input: &str| {
            let ports = separated_list1(tag(","), Self::port);
            let tag = preceded(strip_tag(arg), ports);
            let parser = pair(Negative::parse, tag);

            alt((
                map(parser, |(operator, value)| {
                    value
                        .into_iter()
                        .map(|i| Self::build(operator.clone(), i))
                        .collect()
                }),
                map(Self::parse_single(arg), |value| vec![value]),
            ))
            .parse(input)
        }
    }
}

// --tcp-flags

static TCP_FLAGS_ALL: [&'static str; 6] = ["SYN", "ACK", "FIN", "RST", "URG", "PSH"];

struct TCPFlagsParser;
impl TCPFlagsParser {
    fn parse_all(s: &str) -> IResult<&str, Vec<&str>> {
        let mut res: Vec<&str> = Vec::with_capacity(6);
        res.extend(TCP_FLAGS_ALL);
        tag("ALL").parse(s).map(|(i, _)| (i, res))
    }

    fn parse_item(s: &str) -> IResult<&str, &str> {
        verify(alpha1, |value| TCP_FLAGS_ALL.contains(value)).parse(s)
    }

    fn flags(s: &str) -> IResult<&str, Vec<&str>> {
        alt((
            Self::parse_all,
            value(vec![], tag("NONE")),
            separated_list1(tag(","), Self::parse_item),
            map(Self::parse_item, |v| vec![v]),
        ))
        .parse(s)
    }

    // 1    // 2
    //  --tcp-flags FIN,SYN,ACK ACK
    // ! --tcp-flags FIN,SYN,ACK ACK
    fn parse(s: &str) -> IResult<&str, (d::StringOperator, d::StringOperator)> {
        map(
            pair(
                single_operator,
                preceded(
                    strip_tag("--tcp-flags"),
                    separated_pair(Self::flags, space1, Self::flags),
                ),
            ),
            |(operator, value)| {
                let values: Vec<&str>;

                if operator == d::OperatorType::EQ {
                    values = value
                        .0
                        .into_iter()
                        .filter(|x| !value.1.contains(x))
                        .collect()
                } else {
                    let mut res: Vec<&str> = Vec::with_capacity(6);
                    res.extend(TCP_FLAGS_ALL);
                    values = res.into_iter().filter(|x| !value.0.contains(x)).collect()
                }

                let first = d::StringOperator::new(d::OperatorType::NEQ, values);
                let second: domain::StringOperator<'_> =
                    d::StringOperator::new(d::OperatorType::EQ, value.1);
                return (first, second);
            },
        )
        .parse(s)
    }
}

fn protocol(s: &str) -> IResult<&str, d::StringOperator> {
    let cond = alt((tag("0"), tag("all")));
    let ip = nom::combinator::value("ip", preceded(strip_tag("-p"), cond));

    let value = preceded(strip_tag("-p"), alpha1);

    map(
        pair(single_operator, alt((ip, value))),
        |(operator, value)| d::StringOperator::new(operator, vec![value]),
    )
    .parse(s)
}

fn protocol_number(s: &str) -> IResult<&str, d::IntOperator> {
    let value = preceded(strip_tag("-p"), verify(u16, |value| *value != 0));

    map(pair(single_operator, value), |(operator, value)| {
        d::IntOperator::new(operator, vec![value])
    })
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
    TCPFlags((d::StringOperator<'a>, d::StringOperator<'a>)),
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
            map(PortParser::parse_vec("--ports"), |value| {
                Token::Ports(value)
            }),
            map(
                alt((
                    PortParser::parse_vec("--sports"),
                    map(PortParser::parse_single("--sport"), |value| vec![value]),
                )),
                |value| Token::SourcePorts(value),
            ),
            map(
                alt((
                    PortParser::parse_vec("--dports"),
                    map(PortParser::parse_single("--dport"), |value| vec![value]),
                )),
                |value| Token::DestinationPorts(value),
            ),
            map(protocol, |value| Token::Protocol(value)),
            map(protocol_number, |value| Token::ProtocolNumber(value)),
            map(TCPFlagsParser::parse, |value| Token::TCPFlags(value)),
            map(unknown_part, |value| Token::Error(value)),
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
