use nom::{
    branch::alt,
    bytes::complete::{tag, take, take_until},
    character::complete::{alpha1, line_ending, not_line_ending, space1, u16},
    combinator::{eof, map, map_parser, not, opt, peek, recognize, rest_len, value, verify},
    multi::{fold_many1, separated_list1},
    sequence::{pair, preceded, separated_pair, terminated},
    IResult, Parser,
};
use serde_derive::Serialize;
use std::cmp;
use std::str::FromStr;

use common::single_or_pair_u16;
use d::BuildIntOperator;
use d::BuildOperatorType;
use domain as d;
use domain::Builder;
use macros::BuildOperatorType;

type ActionType = d::nftables::ActionType;
type ActionSetting<'a> = d::ActionSetting<'a, ActionType>;

#[derive(Debug, PartialEq, Eq)]
pub struct ParseEnum2Error; // TODO нормальное название

#[cfg(test)]
mod tests {
    use super::*;
    use tester::tester;

    #[tester("acl.toml")]
    fn test_rule(arg: &str) -> IResult<&str, d::nftables::ACLRule<ActionType>> {
        let v = vec!["MY_CHAIN"];
        rule(arg, &v)
    }

    #[tester("parser.toml")]
    fn test_parser(arg: &str) -> IResult<&str, RawACLRule> {
        parser(arg, |_| false)
    }

    #[tester("protocol.toml")]
    fn test_protocol(arg: &str) -> IResult<&str, d::Protocol> {
        protocol(arg)
    }

    #[test]
    fn test_flag() {
        assert_eq!(flag_value("SYN").unwrap(), ("", vec!["SYN"]));
        assert_eq!(
            flag_value("FIN,SYN,ACK").unwrap(),
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

        let (remaining, result) = until_eof("\ndf").unwrap();
        assert_eq!(remaining, "\ndf");
        assert_eq!(result, "");
    }

    #[test]
    fn test_unknown_part() {
        let (remaining, result) = unknown_part(" ").unwrap();
        assert_eq!(remaining, "");
        assert_eq!(result, " ");

        let (remaining, result) =
            unknown_part(" --match-set BlockedHosts dst,dst -j DROP").unwrap();
        assert_eq!(remaining, " -j DROP");
        assert_eq!(result, " --match-set BlockedHosts dst,dst");

        let (remaining, result) = unknown_part(" --match-set BlockedHosts dst,dst").unwrap();
        assert_eq!(remaining, "");
        assert_eq!(result, " --match-set BlockedHosts dst,dst");

        let (remaining, result) = unknown_part(" --log-ip-options\ns").unwrap();
        assert_eq!(remaining, "\ns");
        assert_eq!(result, " --log-ip-options");

        // точки останова
        assert_eq!(
            unknown_part(""),
            Err(nom::Err::Error(nom::error::Error {
                input: "",
                code: nom::error::ErrorKind::Not
            }))
        );

        assert_eq!(
            unknown_part("\ns"),
            Err(nom::Err::Error(nom::error::Error {
                input: "\ns",
                code: nom::error::ErrorKind::Not
            }))
        )
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
    move |input: &str| preceded(pair(tag(arg), space1), until_eof).parse(input)
}

fn tag_value(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded_tag(arg, until_eof).parse(input)
}

fn unknown_part(input: &str) -> IResult<&str, &str> {
    not(alt((eof, line_ending))).parse(input)?;

    recognize(pair(opt(alt((tag(" -"), tag(" !")))), until_eof)).parse(input)
}
/*

BuildIntOperator -> d::OperatorType

#[derive(BuildIntOperator)]
struct OtherValue(bool);
impl OtherValue {
    fn parse(s: &str) -> IResult<&str, Self> {
        какой то свой парсинг из строки
    }
}

*/

#[derive(Serialize, Clone, PartialEq, BuildOperatorType)]
struct Negative(bool);

impl Default for Negative {
    fn default() -> Self {
        Self(false)
    }
}

fn operator(s: &str) -> IResult<&str, Negative> {
    let operator_ = value(Negative(true), tag("!"));

    map(opt(terminated(operator_, space1)), |v| {
        v.unwrap_or_default()
    })
    .parse(s)
}

fn single_operator(s: &str) -> IResult<&str, d::OperatorType> {
    map(operator, |v| v.single()).parse(s)
}

use nom::error::ParseError;

pub fn preceded_tag<'a, T, E: ParseError<&'a str>, F>(
    arg: &'static str,
    f: F,
) -> impl Parser<&'a str, T, E>
where
    F: Parser<&'a str, T, E>,
{
    preceded(pair(tag(arg), space1), f)
}

pub fn separated_by_colon<'a, T, E: ParseError<&'a str>, F>(f: F) -> impl Parser<&'a str, Vec<T>, E>
where
    F: Parser<&'a str, T, E>,
{
    separated_list1(tag(","), f)
}

fn pair_sep_colon(s: &str) -> IResult<&str, d::SingleOrPair<u16>> {
    single_or_pair_u16(":").parse(s)
}

struct PortParser;

impl PortParser {
    //  IntOperator --sport 500:600 --dport 45
    // ! --ports 50,300:400
    // --ports 50

    fn parse(arg: &'static str) -> impl Fn(&str) -> IResult<&str, Vec<d::IntOperator>> {
        move |input: &str| {
            let port = map(pair_sep_colon, |v| vec![v]);

            let ports = separated_by_colon(pair_sep_colon);

            map(
                pair(single_operator, preceded_tag(arg, alt((port, ports)))),
                |(operator, value)| {
                    {
                        value
                            .into_iter()
                            .map(|i| Self::build(operator.clone(), i))
                            .collect()
                    }
                },
            )
            .parse(input)
        }
    }
}

impl BuildIntOperator for PortParser {} // TODO нужно ли тут Trait может просто функция?
                                        // --tcp-flags

static TCP_FLAGS_ALL: [&str; 6] = ["SYN", "ACK", "FIN", "RST", "URG", "PSH"];

fn build_tcp_flags<'a>(
    operator: d::OperatorType,
    value: (Vec<&'a str>, Vec<&'a str>),
) -> (d::StringOperator<'a>, d::StringOperator<'a>) {
    let values: Vec<&str>;

    if operator == d::OperatorType::EQ {
        values = value
            .0
            .into_iter()
            .filter(|x| !value.1.contains(x))
            .collect()
    } else {
        values = TCP_FLAGS_ALL
            .into_iter()
            .filter(|x| !value.0.contains(x))
            .collect()
    }

    let first = d::StringOperator::new(d::OperatorType::NEQ, values);
    let second: domain::StringOperator<'_> = d::StringOperator::new(d::OperatorType::EQ, value.1);

    (first, second)
}

fn flag_value(s: &str) -> IResult<&str, Vec<&str>> {
    let none = value(vec![], tag("NONE"));

    let mut all_flags: Vec<&str> = Vec::with_capacity(6);
    all_flags.extend(TCP_FLAGS_ALL);

    let all = value(all_flags, tag("ALL"));

    fn item(s: &str) -> IResult<&str, &str> {
        verify(alpha1, |value| TCP_FLAGS_ALL.contains(value)).parse(s)
    }

    let single = map(item, |v| vec![v]);
    let pair = separated_by_colon(item);

    alt((none, all, pair, single)).parse(s)
}

// _____________ 1    // 2
//  --tcp-flags FIN,SYN,ACK ACK
// ! --tcp-flags FIN,SYN,ACK ACK
fn tcp_flags(s: &str) -> IResult<&str, (d::StringOperator, d::StringOperator)> {
    map(
        pair(
            single_operator,
            preceded_tag(
                "--tcp-flags",
                separated_pair(flag_value, space1, flag_value),
            ),
        ),
        |(operator, value)| build_tcp_flags(operator, value),
    )
    .parse(s)
}

fn protocol(s: &str) -> IResult<&str, d::Protocol> {
    let any = value(
        d::StringOrU16::String("ip"),
        preceded_tag("-p", alt((tag("0"), tag("all")))),
    );
    let string = map(preceded_tag("-p", alpha1), d::StringOrU16::String);
    let number = map(
        preceded_tag("-p", verify(u16, |value| *value != 0)),
        d::StringOrU16::Number,
    );

    map(
        pair(single_operator, alt((any, string, number))),
        |(operator, value)| d::Protocol::new(operator, value),
    )
    .parse(s)
}

fn ip_options<'a>(s: &'a str) -> IResult<&'a str, ActionSetting<'a>> {
    let parser1 = alt((
        value(ActionType::LogTCPSequence, tag("--log-tcp-sequence")),
        value(ActionType::LogTCPOptions, tag("--log-tcp-options")),
        value(ActionType::LogIPOptions, tag("--log-ip-options")),
    ));

    let parser2 = alt((
        value(ActionType::LogLevel, tag("--log-level")),
        value(ActionType::LogPrefix, tag("--log-prefix")),
    ));

    let parser3 = separated_pair(parser2, space1, until_eof);

    alt((
        map(parser1, |v| d::ActionSetting::new(v, "")),
        map(parser3, |(action, option)| {
            ActionSetting::new(action, option)
        }),
    ))
    .parse(s)
}

#[derive(Serialize)]
enum OptionType<'a> {
    Goto(&'a str),
    Jump(&'a str),
    Value(&'a str),
}

// представление правила в плоской структуре
#[derive(Serialize, Default)]
struct RawACLRule<'a> {
    #[serde(skip_serializing_if="d::is_empty")]
    action_modifiers: Vec<ActionSetting<'a>>,
    name: Option<&'a str>,
    #[serde(flatten)]
    protocol: Option<d::Protocol<'a>>,
    #[serde(skip_serializing_if="d::is_empty")]
    sports: Vec<d::IntOperator>,
    #[serde(skip_serializing_if="d::is_empty")]
    dports: Vec<d::IntOperator>,
    #[serde(skip_serializing_if="d::is_empty")]
    ports: Vec<d::IntOperator>,
    tcp_flags: Option<(d::StringOperator<'a>, d::StringOperator<'a>)>,
    action: Option<ActionType>,
    option: Option<OptionType<'a>>,
}
impl<'a> RawACLRule<'a> {
    fn add(&mut self, token: Token<'a>) {
        match token {
            Token::Error(v) => debug!("Error: {:?}", v),
            Token::Action(v) => self.action = Some(v),
            Token::Option(v) => self.option = Some(v),
            Token::ActionModifier(v) => self.action_modifiers.push(v),
            Token::Name(v) => self.name = Some(v),
            Token::Protocol(v) => self.protocol = Some(v),
            Token::Ports(v) => self.ports = v,
            Token::SourcePorts(v) => self.sports = v,
            Token::DestinationPorts(v) => self.dports = v,
            Token::TCPFlags(v) => self.tcp_flags = Some(v),
            Token::Space => (),
        }
    }
}

impl<'a> d::Builder for RawACLRule<'a> {
    type Result = d::nftables::ACLRule<'a, d::nftables::ActionType>;

    fn build(self) -> Self::Result {
        let mut action_bulder = d::ActionSettingBuilder::default();

        if let Some(v) = self.option {
            match v {
                OptionType::Goto(v) => action_bulder.action(Some(ActionType::GOTO)).option(Some(v)),
                OptionType::Jump(v) => action_bulder.action(Some(ActionType::JUMP)).option(Some(v)),
                OptionType::Value(v) => action_bulder.option(Some(v)),
            };
        }
        action_bulder.action(self.action);

        let mut acl_rule = ACLRuleBuilder::default();

        acl_rule.action(action_bulder, self.action_modifiers);

        let mut tcp_udp_options = d::TCPUDPOptions::default();

        tcp_udp_options
            .source_ports(self.sports)
            .source_ports(self.ports.clone())
            .destination_ports(self.dports)
            .destination_ports(self.ports);
        
        if let Some(v) = self.tcp_flags {
            tcp_udp_options.flags(vec![v.0, v.1]);
        }

        if let Some(v) =  self.protocol {
            acl_rule.protocol(v, tcp_udp_options.build());
        }

        acl_rule.build()
    }
}

enum Token<'a> {
    Action(ActionType),
    ActionModifier(d::ActionSetting<'a, ActionType>),
    DestinationPorts(Vec<d::IntOperator>),
    Error(&'a str),
    Space,
    Name(&'a str),
    Option(OptionType<'a>),
    Ports(Vec<d::IntOperator>),
    Protocol(d::Protocol<'a>),
    SourcePorts(Vec<d::IntOperator>),
    TCPFlags((d::StringOperator<'a>, d::StringOperator<'a>)),
}

fn parser<F>(input: &str, is_user_chain: F) -> IResult<&str, RawACLRule>
where
    F: Fn(&str) -> bool,
{
    let parser = alt((
        map(name("-A"), Token::Name),
        map(verify(tag_value("-j"), is_user_chain), |value| {
            Token::Option(OptionType::Jump(value))
        }),
        map(
            verify(tag_value("-j"), |value| ActionType::from_str(value).is_ok()),
            |value| Token::Action(ActionType::from_str(value).unwrap()),
        ),
        map(tag_value("--reject-with"), |v| {
            Token::Option(OptionType::Value(v))
        }),
        map(tag_value("-g"), |value| {
            Token::Option(OptionType::Goto(value))
        }),
        map(ip_options, Token::ActionModifier),
        map(PortParser::parse("--ports"), Token::Ports),
        map(
            alt((PortParser::parse("--sports"), PortParser::parse("--sport"))),
            Token::SourcePorts,
        ),
        map(
            alt((PortParser::parse("--dports"), PortParser::parse("--dport"))),
            Token::DestinationPorts,
        ),
        map(protocol, Token::Protocol),
        map(tcp_flags, Token::TCPFlags),
        map(space1, |_| Token::Space),
        map(unknown_part, Token::Error),
    ));

    fold_many1(parser, RawACLRule::default, |mut acc, item: Token| {
        acc.add(item);
        acc
    })
    .parse(input)
}

#[derive(Serialize)]
struct ActionModifiers<'a>(Vec<ActionSetting<'a>>);
impl<'a> ActionModifiers<'a> {
    fn push(&mut self, item: ActionSetting<'a>) {
        if item.is_type(ActionType::LogLevel) {
            self.0[0] = item
        } else {
            self.0.push(item)
        }
    }
}

impl Default for ActionModifiers<'_> {
    fn default() -> Self {
        Self(vec![d::ActionSetting::new(ActionType::LogLevel, "warning")])
    }
}

#[derive(Default)]
pub struct ACLRuleBuilder<'a, T> {
    action_modifiers: Vec<d::ActionSetting<'a, T>>,
    action: Option<d::ActionSetting<'a, T>>,
    normalized_action: Option<d::NormalizedAction>,
    protocol: Option<d::ProtocolSetting<'a, d::IPv4Options>>,
}

impl<'a> ACLRuleBuilder<'a, ActionType> {
    fn action(
        &mut self,
        builder: d::ActionSettingBuilder<'a, ActionType>,
        action_modifiers: Vec<ActionSetting<'a>>,
    ) -> &mut Self {
        let action = builder.build();

        if let Some(i) = action {
            self.normalized_action = i.normalized_action().ok();

            if i.is_type(ActionType::LOG) {
                let mut action_modifiers_builder = ActionModifiers::default();
                action_modifiers
                    .into_iter()
                    .for_each(|i| action_modifiers_builder.push(i));

                self.action_modifiers = action_modifiers_builder.0
            }

            self.action = Some(i);
        }
        self
    }
    fn protocol(
        &mut self,
        protocol: d::Protocol<'a>,
        tcp_upd_options: d::TCPUDPOptions<'a>,
    ) -> &mut Self {
        self.protocol = Some(d::ProtocolSetting::new(
            None,
            protocol,
            Some(tcp_upd_options),
            None,
            None,
        ));
        self
    }
}

impl<'a> d::Builder for ACLRuleBuilder<'a, ActionType> {
    // для каждого типа T который реализует Builder<Result = domain::ActionSetting> будет создана своя версия action<конкретный тип>
    // тип Builder дропается в build()
    // все билдеры одноразовые

    type Result = d::nftables::ACLRule<'a, d::nftables::ActionType>;

    fn build(self) -> Self::Result {
        if let Some(i) = self.action {
            return d::nftables::ACLRule::new(
                vec![i],
                self.action_modifiers,
                self.normalized_action,
                self.protocol
            );
        } else {
            d::nftables::ACLRule::new(vec![], vec![], None, None)
        }
    }
}

pub fn rule<'a>(
    input: &'a str,
    user_chains: &Vec<&'a str>,
) -> IResult<&'a str, d::nftables::ACLRule<'a, ActionType>> {
    let (remain, rule) = parser(input, |v| user_chains.contains(&v))?;

    Ok((remain, rule.build()))
}
