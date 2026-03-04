use nom::{
    branch::alt,
    bytes::complete::{tag, take, take_until},
    character::complete::{alpha1, hex_digit1, line_ending, not_line_ending, space1, u16},
    combinator::{eof, map, map_parser, not, opt, peek, recognize, rest_len, value, verify},
    multi::fold_many1,
    sequence::{pair, preceded, separated_pair, terminated},
    IResult, Parser,
};
use serde_derive::Serialize;
use std::cmp;
use std::str::FromStr;

use c::{pair_sep_colon, preceded_tag, separated_by_comma};
use common as c;
use d::BuildOperatorType;
use domain::Builder;
use domain::{self as d};
use macros::in_not_null;
use macros::BuildOperatorType;
use macros::{alt_impl, Mapping};

type ActionType = d::nftables::ActionType;
type ActionSetting<'a> = d::ActionSetting<'a, ActionType>;
type ACLRule<'a> = d::ACLRule<'a, ActionType, d::IPv4Options>;
type ProtocolSetting<'a> = d::ProtocolSetting<'a, d::IPv4Options>;

#[cfg(test)]
mod tests {
    use super::*;
    use tester::tester;

    #[tester("acl.toml")]
    fn test_rule<'a>(arg: &'a str) -> IResult<&'a str, ACLRule<'a>> {
        let v = vec!["MY_CHAIN"];
        rule(arg, &v)
    }

    #[tester("parser.toml")]
    fn test_parser<'a>(arg: &'a str) -> IResult<&'a str, RawACLRule<'a>> {
        parser(arg, |_| false)
    }

    #[tester("protocol.toml")]
    fn test_protocol<'a>(arg: &'a str) -> IResult<&'a str, d::Protocol<'a>> {
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
    fn test_dscp() {
        let (rem, res) = dscp("--dscp 0x20").unwrap();
        assert_eq!("", rem);
        assert_eq!(
            "operator = \"eq\"\nvalues = [32]\n",
            toml::to_string(&res).unwrap()
        )
    }

    #[test]
    fn test_length() {
        let (rem, res) = length("--length 300").unwrap();
        assert_eq!("", rem);
        assert_eq!(
            "operator = \"eq\"\nvalues = [300]\n",
            toml::to_string(&res).unwrap()
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

#[derive(Serialize, Clone, PartialEq, BuildOperatorType)]
struct Operator<T>(T);

impl Default for Operator<bool> {
    fn default() -> Self {
        Self(false)
    }
}

impl Operator<bool> {
    fn fragment_operator(&self) -> d::IntOperator {
        match self.0 {
            true => d::IntOperator::new(d::OperatorType::MatchAny, vec![0, 1]),
            false => d::IntOperator::new(d::OperatorType::GT, vec![1]),
        }
    }
}

fn operator(s: &str) -> IResult<&str, Operator<bool>> {
    let operator_ = value(Operator(true), tag("!"));

    map(opt(terminated(operator_, space1)), |v| {
        v.unwrap_or_default()
    })
    .parse(s)
}

fn single_operator(s: &str) -> IResult<&str, d::OperatorType> {
    map(operator, |v| v.single()).parse(s)
}

// # основной вывод:
// --ttl-gt 200
// еще пример
// --ttl-eq 100
//--ttl-gt 200
fn ttl(s: &str) -> IResult<&str, d::IntOperator> {
    // --ttl-eq
    // --ttl-gt
    // --ttl-lt
    let ttl_operator = alt((
        value(d::OperatorType::EQ, tag("eq")),
        value(d::OperatorType::GT, tag("gt")),
        value(d::OperatorType::LT, tag("lt")),
    ));

    let ttl_parser = separated_pair(preceded(tag("--ttl-"), ttl_operator), space1, u16);

    c::single_int_operator(ttl_parser).parse(s)
}

// -f ! -f
fn fragment(s: &str) -> IResult<&str, d::IntOperator> {
    map(
        pair(map(operator, |v| v.fragment_operator()), tag("-f")),
        |pair| pair.0,
    )
    .parse(s)
}

// --dscp 0x20
fn dscp(s: &str) -> IResult<&str, d::IntOperator> {
    let tag_ = pair(tag("--dscp"), space1);
    let value = preceded(tag("0x"), hex_digit1);

    let parser = map(preceded(tag_, value), |v| {
        u16::from_str_radix(v, 16).unwrap()
    });

    c::dscp(parser).parse(s)
}

// --length 300
// --length 300:301
// --length !300:301
fn length(s: &str) -> IResult<&str, d::IntOperator> {
    let tag_ = pair(tag("--length"), space1);
    let value = pair(operator, pair_sep_colon);
    let parser = preceded(tag_, value);

    c::int_operator(parser).parse(s)
}

fn ip_protocol_options(s: &str) -> IResult<&str, d::IntOperator> {
    // [!] --rr  = 7
    // [!] --ts = 68
    // [!] --ra = 148
    let parser = pair(
        single_operator,
        alt((
            value(7, tag("--rr")),
            value(68, tag("--ts")),
            value(148, tag("--ra")),
        )),
    );

    alt((
        c::single_int_operator(parser),
        // --ssrr = eq 137
        // --lsrr = eq 131
        // --no-srr = neq [131, 137]
        //--any-opt  = eq 0
        alt((
            value(
                d::IntOperator::new(d::OperatorType::EQ, vec![137]),
                tag("--ssrr"),
            ),
            value(
                d::IntOperator::new(d::OperatorType::EQ, vec![131]),
                tag("--lsrr"),
            ),
            value(
                d::IntOperator::new(d::OperatorType::NEQ, vec![131, 137]),
                tag("--no-srr"),
            ),
            value(
                d::IntOperator::new(d::OperatorType::EQ, vec![0]),
                tag("--any-opt"),
            ),
        )),
    ))
    .parse(s)
}

//  IntOperator --sport 500:600 --dport 45
// ! --ports 50,300:400
// --ports 50
fn port(arg: &'static str) -> impl Fn(&str) -> IResult<&str, Vec<d::IntOperator>> {
    move |input: &str| {
        let port = map(pair_sep_colon, |v| vec![v]);
        let ports = separated_by_comma(pair_sep_colon);

        let parser = pair(operator, preceded_tag(arg, alt((port, ports))));

        c::many_int_operator(parser).parse(input)
    }
}

pub fn flag_value(s: &str) -> IResult<&str, Vec<&str>> {
    let none = value(vec![], tag("NONE"));

    let mut all_flags: Vec<&str> = Vec::with_capacity(6);
    all_flags.extend(c::TCP_FLAGS_ALL);

    let all = value(all_flags, tag("ALL"));

    fn item(s: &str) -> IResult<&str, &str> {
        verify(alpha1, |value| c::TCP_FLAGS_ALL.contains(value)).parse(s)
    }

    let single = map(item, |v| vec![v]);
    let pair = separated_by_comma(item);

    alt((none, all, pair, single)).parse(s)
}

// _____________ 1    // 2
//  --tcp-flags FIN,SYN,ACK ACK
// ! --tcp-flags FIN,SYN,ACK ACK
fn tcp_flags<'a>(s: &'a str) -> IResult<&'a str, (d::StringOperator<'a>, d::StringOperator<'a>)> {
    let parser = pair(
        single_operator,
        preceded_tag(
            "--tcp-flags",
            separated_pair(flag_value, space1, flag_value),
        ),
    );

    c::tcp_flags(parser).parse(s)
}

fn protocol<'a>(s: &'a str) -> IResult<&'a str, d::Protocol<'a>> {
    let number = verify(u16, |value| *value != 0);

    let protocol = alt((
        value(d::StringOrU16::String("ip"), alt((tag("0"), tag("all")))),
        map(alpha1, d::StringOrU16::String),
        map(number, d::StringOrU16::Number),
    ));

    let parser = pair(single_operator, preceded_tag("-p", protocol));

    c::protocol(parser).parse(s)
}

fn ip_options<'a>(s: &'a str) -> IResult<&'a str, ActionSetting<'a>> {
    let tag_parser = alt((
        value(ActionType::LogTCPSequence, tag("--log-tcp-sequence")),
        value(ActionType::LogTCPOptions, tag("--log-tcp-options")),
        value(ActionType::LogIPOptions, tag("--log-ip-options")),
    ));

    let value_parser = alt((
        value(ActionType::LogLevel, tag("--log-level")),
        value(ActionType::LogPrefix, tag("--log-prefix")),
    ));

    alt((
        map(tag_parser, |v| d::ActionSetting::new(v, "")),
        map(
            separated_pair(value_parser, space1, until_eof),
            |(action, option)| ActionSetting::new(action, option),
        ),
    ))
    .parse(s)
}

#[derive(Serialize)]
enum OptionType<'a> {
    Goto(&'a str),
    Jump(&'a str),
    Value(&'a str),
}

trait Mapping<T> {
    fn mapping(&mut self, target: T);
}

// представление правила в плоской структуре
#[derive(Mapping, Serialize, Default)]
#[mapping(Token)]
#[mapping(ActionModifier = action_modifier)]
#[mapping(IPProtocolOption = ip_protocol_option)]
#[mapping(Error = error)]
struct RawACLRule<'a> {
    #[serde(skip_serializing_if = "d::is_empty")]
    #[mapping(skip)]
    action_modifiers: Vec<ActionSetting<'a>>,
    #[mapping(skip)]
    log_level: Option<ActionSetting<'a>>,
    name: Option<&'a str>,
    #[serde(flatten)]
    protocol: Option<d::Protocol<'a>>,
    #[serde(skip_serializing_if = "d::is_empty")]
    source_ports: Vec<d::IntOperator>,
    #[serde(skip_serializing_if = "d::is_empty")]
    destination_ports: Vec<d::IntOperator>,
    #[serde(skip_serializing_if = "d::is_empty")]
    ports: Vec<d::IntOperator>,
    #[mapping(rename = TCPFlags)]
    tcp_flags: Option<(d::StringOperator<'a>, d::StringOperator<'a>)>,
    action: Option<ActionType>,
    option: Option<OptionType<'a>>,
    #[mapping(rename = TTL)]
    ttl: Option<d::IntOperator>,
    fragment: Option<d::IntOperator>,
    #[mapping(rename = DSCP)]
    dscp: Option<d::IntOperator>,
    packet_length: Option<d::IntOperator>,
    #[serde(skip_serializing_if = "d::is_empty")]
    #[mapping(skip)]
    ip_protocol_options: Vec<d::IntOperator>,
}

impl<'a> RawACLRule<'a> {
    fn action_modifier(&mut self, v: d::ActionSetting<'a, ActionType>) {
        if v.is_type(ActionType::LogLevel) {
            self.log_level = Some(v)
        } else {
            self.action_modifiers.push(v)
        }
    }
    fn ip_protocol_option(&mut self, v: d::IntOperator) {
        self.ip_protocol_options.push(v)
    }

    fn error(&mut self, v: &'a str) {
        debug!("Error: {:?}", v)
    }
}

fn action_setting<'a>(
    action: Option<ActionType>,
    option: Option<OptionType<'a>>,
) -> ActionSetting<'a> {
    match (action, option) {
        (Some(action), Some(option)) => {
            if let OptionType::Value(v) = option {
                return ActionSetting::new(action, v);
            }
        }
        (Some(action), None) => return ActionSetting::new(action, Default::default()),
        (None, Some(option)) => match option {
            OptionType::Goto(v) => return ActionSetting::new(ActionType::GOTO, v),
            OptionType::Jump(v) => return ActionSetting::new(ActionType::JUMP, v),
            OptionType::Value(_) => (),
        },
        (None, None) => (),
    }
    return ActionSetting::default();
}

fn action_modifiers<'a>(
    action: &Option<ActionType>,
    log_level: Option<ActionSetting<'a>>,
    action_modifiers: Vec<ActionSetting<'a>>,
) -> Vec<ActionSetting<'a>> {
    let first = match (action, log_level) {
        (Some(ActionType::LOG), Some(v)) => v,
        (Some(ActionType::LOG), None) => d::ActionSetting::new(ActionType::LogLevel, "warning"),
        _ => return vec![],
    };
    let mut result = Vec::with_capacity(action_modifiers.len() + 1);
    result.push(first);
    result.extend(action_modifiers);
    result
}

#[in_not_null(all)]
fn tcp_udp_options<'a>(
    sports: Vec<d::IntOperator>,
    dports: Vec<d::IntOperator>,
    ports: Vec<d::IntOperator>,
    tcp_flags: Option<(d::StringOperator<'a>, d::StringOperator<'a>)>,
) -> Option<d::TCPUDPOptions<'a>> {
    Some(d::TCPUDPOptions::new(
        sports
            .into_iter()
            .chain(ports.clone().into_iter())
            .collect(),
        dports.into_iter().chain(ports.into_iter()).collect(),
        tcp_flags.map_or(vec![], |v| vec![v.0, v.1]),
    ))
}

#[in_not_null(all)]
fn ip_v_4options(
    ttl: Option<d::IntOperator>,
    fragment: Option<d::IntOperator>,
    dscp: Option<d::IntOperator>,
    packet_length: Option<d::IntOperator>,
    ip_protocol_options: Vec<d::IntOperator>,
) -> Option<d::IPv4Options> {
    Some(d::IPv4Options::new(
        fragment.map_or(vec![], |v| vec![v]),
        dscp.map_or(vec![], |v| vec![v]),
        vec![],
        ip_protocol_options,
        ttl.map_or(vec![], |v| vec![v]),
        packet_length.map_or(vec![], |v| vec![v]),
    ))
}

fn protocol_setting<'a>(
    protocol: d::Protocol<'a>,
    tcp_udp_options: Option<d::TCPUDPOptions<'a>>,
    ip_options: Option<d::IPv4Options>,
) -> d::ProtocolSetting<'a, d::IPv4Options> {
    d::ProtocolSetting::new(None, protocol, tcp_udp_options, ip_options, None)
}

fn acl<'a>(
    action: ActionSetting<'a>,
    action_modifiers: Vec<ActionSetting<'a>>,
    normalized_action: Option<d::NormalizedAction>,
    protocol: ProtocolSetting<'a>,
) -> ACLRule<'a> {
    ACLRule::new(
        vec![action],
        action_modifiers,
        normalized_action,
        None,
        Some(protocol),
    )
}

impl<'a> d::Builder for RawACLRule<'a> {
    type Result = ACLRule<'a>;

    fn build(self) -> Self::Result {
        let action_modifiers =
            action_modifiers(&self.action, self.log_level, self.action_modifiers);
        let action = action_setting(self.action, self.option);
        let normalized_action = action.normalized_action().ok();

        acl(
            action,
            action_modifiers,
            normalized_action,
            protocol_setting(
                self.protocol.unwrap_or(d::Protocol::ip()),
                tcp_udp_options(
                    self.source_ports,
                    self.destination_ports,
                    self.ports,
                    self.tcp_flags,
                ),
                ip_v_4options(
                    self.ttl,
                    self.fragment,
                    self.dscp,
                    self.packet_length,
                    self.ip_protocol_options,
                ),
            ),
        )
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
    TTL(d::IntOperator),
    Fragment(d::IntOperator),
    DSCP(d::IntOperator),
    PacketLength(d::IntOperator),
    IPProtocolOption(d::IntOperator),
}

impl<'a> Token<'a> {
    fn action(v: &'a str) -> Self {
        Self::Action(ActionType::from_str(v).unwrap())
    }
    fn goto(v: &'a str) -> Self {
        Self::Option(OptionType::Goto(v))
    }
    fn jump(v: &'a str) -> Self {
        Self::Option(OptionType::Jump(v))
    }
    fn option(v: &'a str) -> Self {
        Self::Option(OptionType::Value(v))
    }
    fn space(_: &'a str) -> Self {
        Token::Space
    }
}

fn parser<F>(input: &'_ str, is_user_chain: F) -> IResult<&'_ str, RawACLRule<'_>>
where
    F: Fn(&str) -> bool,
{
    let parser = alt_impl!(
        Token,
        "Name" = name("-A"),
        "jump" = verify(tag_value("-j"), is_user_chain),
        "action" = verify(tag_value("-j"), |value| ActionType::from_str(value).is_ok()),
        "option" = tag_value("--reject-with"),
        "goto" = tag_value("-g"),
        "ActionModifier" = ip_options,
        "Ports" = port("--ports"),
        "SourcePorts" = alt((port("--sports"), port("--sport"))),
        "DestinationPorts" = alt((port("--dports"), port("--dport"))),
        "Protocol" = protocol,
        "TCPFlags" = tcp_flags,
        "TTL" = ttl,
        "DSCP" = dscp,
        "Fragment" = fragment,
        "PacketLength" = length,
        "IPProtocolOption" = ip_protocol_options,
        "space" = space1,
        "Error" = unknown_part,
    );

    fold_many1(parser, RawACLRule::default, |mut acc, item: Token| {
        acc.mapping(item);
        acc
    })
    .parse(input)
}

pub fn rule<'a>(input: &'a str, user_chains: &Vec<&'a str>) -> IResult<&'a str, ACLRule<'a>> {
    let (remain, rule) = parser(input, |v| user_chains.contains(&v))?;

    Ok((remain, rule.build()))
}
