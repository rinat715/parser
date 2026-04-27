use nom::{
    branch::alt,
    bytes::complete::{tag, take, take_until},
    character::complete::{alpha1, hex_digit1, line_ending, not_line_ending, space1, u16},
    combinator::{eof, map, map_parser, not, opt, peek, recognize, rest_len, value, verify},
    multi::fold_many1,
    sequence::{pair, preceded, separated_pair, terminated, tuple},
    IResult, Parser,
};
use serde_derive::Serialize;
use std::cmp;
use std::str::FromStr;

use crate::domain::{self as d};
use crate::parser::{self as p};
use crate::parser::{preceded_tag_space, separated_by_comma, SingleOrPairU16};
use d::BuildOperatorType;
use d::Merge;
use macros::{alt_impl, is_not_null};

type Operator = d::nftables::OperatorType;
type ActionType = d::nftables::ActionType;
type ACLRule<'a> = d::nftables::ACLRule<'a>;
type ActionSetting<'a> = d::nftables::ActionSetting<'a>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use toml::Table;
    use toml::Value;

    use serde_derive::Deserialize;

    #[derive(Deserialize)]
    struct TestSuit {
        input: String,
        remaining: String,
        expected: Value,
    }

    use fixtures::fixtures;

    fn assert_remaining_wrap(
        path: &std::path::Path,
        name: &str,
        test_remaining: &str,
        remaining: &str,
    ) {
        let file_path = path.to_string_lossy();

        assert_eq!(
            test_remaining,
            remaining,
            "{}",
            diff::Diff::new(&file_path, name, remaining, test_remaining)
        );
    }

    fn assert_eq_wrap<T, T1>(path: &std::path::Path, name: &str, actual_obj: &T, expected_obj: &T1)
    where
        T: serde::Serialize,
        T1: serde::Serialize,
    {
        let actual = toml::to_string(&actual_obj).unwrap();
        let expected = toml::to_string(&expected_obj).unwrap();
        let file_path = path.to_string_lossy();

        assert_eq!(
            actual,
            expected,
            "{}",
            diff::Diff::new(&file_path, name, &actual, &expected)
        );
    }

    #[fixtures(["acl.toml"])]
    #[test]
    fn test_rule(path: &std::path::Path) {
        let contents = fs::read_to_string(&path).expect("Should have been able to read the file");

        let interfaces = vec![String::from("swp1"), String::from("swp2")];
        let user_chains = vec![String::from("MY_CHAIN")];

        for (test_name, value) in contents.parse::<Table>().unwrap() {
            let test: TestSuit = value.try_into().unwrap();
            let (remaining, result) = rule(&test.input, &interfaces, &user_chains).unwrap();

            assert_remaining_wrap(path, &test_name, &test.remaining, remaining);
            assert_eq_wrap(path, &test_name, &result, &test.expected)
        }
    }

    #[fixtures(["protocol.toml"])]
    #[test]
    fn test_protocol<'a>(path: &std::path::Path) {
        let contents = fs::read_to_string(&path).expect("Should have been able to read the file");
        for (test_name, value) in contents.parse::<Table>().unwrap() {
            let test: TestSuit = value.try_into().unwrap();
            let (remaining, result) = protocol(&test.input).unwrap();

            assert_remaining_wrap(path, &test_name, &test.remaining, remaining);
            assert_eq_wrap(path, &test_name, &result, &test.expected)
        }
    }

    #[test]
    fn test_flag() {
        assert_eq!(TSPFlags::value_("SYN").unwrap(), ("", vec!["SYN"]));
        assert_eq!(
            TSPFlags::value_("FIN,SYN,ACK").unwrap(),
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
    fn test_action_setting() {
        let res = action_setting(
            Some(d::nftables::ActionType::REJECT),
            Some(OptionType::Value("tcp-reset")),
        );
        assert!(res.is_some());
        assert_eq!(
            "action = \"REJECT\"\noption = \"tcp-reset\"\n",
            toml::to_string(&res).unwrap()
        );

        let res = action_setting(None, Some(OptionType::Goto("TEST")));
        assert!(res.is_some());
        assert_eq!(
            "action = \"GOTO\"\noption = \"TEST\"\n",
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

// TODO если name не распарсился то парсинг строки должен валится с ошибкой
fn name(s: &str) -> IResult<&str, &str> {
    tag_value("-A").parse(s)
}

fn tag_value(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded_tag_space(arg, until_eof).parse(input)
}

fn unknown_part(input: &str) -> IResult<&str, &str> {
    not(alt((eof, line_ending))).parse(input)?;

    recognize(pair(opt(alt((tag(" -"), tag(" !")))), until_eof)).parse(input)
}

fn operator(s: &str) -> IResult<&str, Operator> {
    let operator_ = value(d::nftables::EXCLAMATION, tag("!"));
    let parser = opt(terminated(operator_, space1));

    map(parser, |value| Operator::new(value)).parse(s)
}

// https://ipset.netfilter.org/iptables-extensions.man.html

// # основной вывод:
// --ttl-gt 200s
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

    p::IntOperator::parser1(ttl_parser).parse(s)
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
    let parser = map(
        preceded_tag_space("--dscp", preceded(tag("0x"), hex_digit1)),
        |v| u16::from_str_radix(v, 16).unwrap(),
    );

    p::dscp(parser).parse(s)
}

// --length 300
// --length 300:301
// --length !300:301
fn length(s: &str) -> IResult<&str, d::IntOperator> {
    let value = pair(operator, SingleOrPairU16::sep_colon);

    p::IntOperator::parser(preceded_tag_space("--length", value)).parse(s)
}

fn ip_protocol_options(s: &str) -> IResult<&str, d::IntOperator> {
    // [!] --rr  = 7
    // [!] --ts = 68
    // [!] --ra = 148
    let parser = pair(
        map(operator, |v| v.single()),
        alt((
            value(7, tag("--rr")),
            value(68, tag("--ts")),
            value(148, tag("--ra")),
        )),
    );

    let eq_builder = d::IntOperatorBuilder::new(d::OperatorType::EQ);

    alt((
        p::IntOperator::parser1(parser),
        // --ssrr = eq 137
        // --lsrr = eq 131
        // --no-srr = neq [131, 137]
        //--any-opt  = eq 0
        alt((
            value(eq_builder.from_value(137), tag("--ssrr")),
            value(eq_builder.from_value(131), tag("--lsrr")),
            value(
                d::IntOperatorBuilder::new(d::OperatorType::NEQ).from_list(vec![131, 137]),
                tag("--no-srr"),
            ),
            value(eq_builder.from_value(0), tag("--any-opt")),
        )),
    ))
    .parse(s)
}

//  --sport 500:600 --dport 45
// ! --ports 50,300:400
// --ports 50
fn port(arg: &'static str) -> impl Fn(&str) -> IResult<&str, Vec<d::IntOperator>> {
    move |input: &str| {
        let port = map(SingleOrPairU16::sep_colon, |v| vec![v]);
        let ports = separated_by_comma(SingleOrPairU16::sep_colon);

        p::IntOperator::parser_many(pair(operator, preceded_tag_space(arg, alt((port, ports)))))
            .parse(input)
    }
}

// -m conntrack
// -m iprange
fn module(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded_tag_space("-m", tag(arg)).parse(input)
}

//  ! -s 192.168.0.1/32
//  -A OUTPUT -s 192.168.0.1/32 -d 100.100.100.0/24 p icmp -m iprange --srcrange 192.168.0.2-192.168.0.100 ! --dstrange 100.100.100.10-100.100.100.200
// -m conntrack --ctorigsrc 10.10.140.3 --ctorigdst 10.0.0.0/8 ! --ctorigdstport 443
fn ip4_address(arg: &'static str) -> impl Fn(&str) -> IResult<&str, d::EndpointSetting> {
    move |input: &str| {
        map(
            pair(
                map(operator, |v| v.single()),
                preceded_tag_space(arg, p::ip4_adresss),
            ),
            |(operator, ip)| d::EndpointSetting::new(d::IPOperator::new(operator, vec![ip])),
        )
        .parse(input)
    }
}

// --srcrange 192.168.0.2-192.168.0.100 ! --dstrange 100.100.100.10-100.100.100.200
fn ip4_range_address(arg: &'static str) -> impl Fn(&str) -> IResult<&str, d::IPOperator> {
    move |input: &str| {
        map(
            pair(
                map(operator, |v| v.range()),
                preceded_tag_space(arg, separated_pair(p::ip4, tag("-"), p::ip4)),
            ),
            |(operator, (f, s))| {
                d::IPOperator::new(
                    operator,
                    vec![
                        d::IPAddress::new_assert(f, 32),
                        d::IPAddress::new_assert(s, 32),
                    ],
                )
            },
        )
        .parse(input)
    }
}

// This matches on a given arbitrary range of IPv4 addresses
// [!]--src-range ip-ip
// Match source IP in the specified range.
// [!]--dst-range ip-ip
// Match destination IP in the specified range.

pub struct TSPFlags;
impl TSPFlags {
    fn item_(s: &str) -> IResult<&str, &str> {
        verify(alpha1, |value| d::TCP_FLAGS_ALL.contains(value)).parse(s)
    }

    fn value_(s: &str) -> IResult<&str, Vec<&str>> {
        alt((
            value(vec![], tag("NONE")),
            value(Vec::from(d::TCP_FLAGS_ALL), tag("ALL")),
            separated_by_comma(Self::item_),
            map(Self::item_, |v| vec![v]),
        ))
        .parse(s)
    }

    //  --tcp-flags FIN,SYN,ACK ACK
    // ! --tcp-flags FIN,SYN,ACK ACK
    fn parser<'a>(s: &'a str) -> IResult<&'a str, (d::StringOperator<'a>, d::StringOperator<'a>)> {
        p::tcp_flags(pair(
            operator,
            preceded_tag_space(
                "--tcp-flags",
                separated_pair(Self::value_, space1, Self::value_),
            ),
        ))
        .parse(s)
    }
}

fn protocol<'a>(s: &'a str) -> IResult<&'a str, d::Protocol<'a>> {
    let number = verify(u16, |value| *value != 0);

    let protocol = alt((
        value(d::StringOrU16::String("ip"), alt((tag("0"), tag("all")))),
        map(alpha1, d::StringOrU16::String),
        map(number, d::StringOrU16::Number),
    ));

    p::protocol(pair(operator, preceded_tag_space("-p", protocol))).parse(s)
}

fn ip_options<'a>(s: &'a str) -> IResult<&'a str, ActionSetting<'a>> {
    let tag_parser = alt((
        value(ActionType::LogTCPSequence, tag("--log-tcp-sequence")),
        value(ActionType::LogTCPOptions, tag("--log-tcp-options")),
        value(ActionType::LogIPOptions, tag("--log-ip-options")),
    ));

    let value_parser = value(ActionType::LogPrefix, tag("--log-prefix"));

    alt((
        map(tag_parser, |v| d::ActionSetting::new(v, "")),
        map(
            separated_pair(value_parser, space1, until_eof),
            |(action, option)| ActionSetting::new(action, option),
        ),
    ))
    .parse(s)
}

fn log_level<'a>(s: &'a str) -> IResult<&'a str, ActionSetting<'a>> {
    let value_parser = value(ActionType::LogLevel, tag("--log-level"));

    map(
        separated_pair(value_parser, space1, until_eof),
        |(action, option)| ActionSetting::new(action, option),
    )
    .parse(s)
}

// --ctstate INVALID,RELATED,SNAT
// ! --ctstate INVALID,RELATED,SNAT
fn ctstate<'a>(s: &'a str) -> IResult<&'a str, Vec<d::StringOperator<'a>>> {
    let parser = pair(
        operator,
        preceded_tag_space(
            "--ctstate",
            separated_by_comma(alt((
                tag("ESTABLISHED"),
                tag("INVALID"),
                tag("NEW"),
                tag("RELATED"),
                tag("SNAT"),
                tag("DNAT"),
            ))),
        ),
    );
    p::ctstate(parser).parse(s)
}

// -i swp+
// -o swp1
// ! -i swp3,swp4
//
fn interface(
    arg: &'static str,
) -> impl Fn(&str) -> IResult<&str, (d::OperatorType, Vec<p::Interface>)> {
    move |input: &str| {
        let mask_parser = map(terminated(alpha1, tag("+")), |v| p::Interface::Mask(v));
        let value_parser = map(alpha1, |v| p::Interface::Value(v));

        let parser = alt((mask_parser, value_parser));

        pair(
            map(operator, |v| v.single()),
            preceded_tag_space(arg, separated_by_comma(parser)),
        )
        .parse(input)
    }
}

// [!] --match-set setname flag1[,flag2[,...,flagn]]
// --match-set test src,dst
// ! --match-set test src,dst
fn set<'a>(s: &'a str) -> IResult<&'a str, d::SetOperator<'a>> {
    let parser = map(
        tuple((
            operator,
            preceded_tag_space("--match-set", alpha1),
            space1,
            separated_by_comma(alt((
                tag("dst"),
                tag("srcport"),
                tag("dstport"),
                tag("iniface"),
                tag("outiface"),
            ))),
        )),
        |res| (res.0, res.1, res.3),
    );

    p::set(parser).parse(s)
}

#[is_not_null(all)]
fn action_setting<'a>(
    action: Option<ActionType>,
    option: Option<OptionType<'a>>,
) -> Option<ActionSetting<'a>> {
    match (action, option) {
        (Some(action), Some(option)) => {
            if let OptionType::Value(v) = option {
                return Some(ActionSetting::new(action, v));
            }
        }
        (Some(action), None) => return Some(ActionSetting::new(action, Default::default())),
        (None, Some(option)) => match option {
            OptionType::Goto(v) => return Some(ActionSetting::new(ActionType::GOTO, v)),
            OptionType::Jump(v) => return Some(ActionSetting::new(ActionType::JUMP, v)),
            OptionType::Value(_) => (),
        },
        (None, None) => (),
    }
    return None;
}

#[derive(Serialize)]
enum OptionType<'a> {
    Goto(&'a str),
    Jump(&'a str),
    Value(&'a str),
}

pub struct Interface<'a> {
    values: &'a Vec<String>,
}

impl<'a> Interface<'a> {
    pub fn new(interfaces: &'a Vec<String>) -> Self {
        Self { values: interfaces }
    }
}

impl<'a> d::Normalizator for Interface<'a> {
    type Arg = &'a str;
    type Result = Vec<&'a str>;

    fn normalize(&self, value: &Self::Arg) -> Self::Result {
        self.values
            .iter()
            .filter(|v| v.starts_with(value))
            .map(|s| s.as_str())
            .collect()
    }
}

struct RawACLRule<'a> {
    // билдеры
    rule: d::Rule<'a, d::ACL<'a, d::nftables::ActionType>, d::nftables::Vendor<'a>>,
    protocol: d::ProtocolSettingBuilder<'a>,
    extended: d::ACL<'a, d::nftables::ActionType>,
    vendor: d::nftables::Vendor<'a>,
    interface: Interface<'a>,
    // шаред поля
    name: Option<&'a str>,
    conntrack: bool,
    ip_range: bool,
    ip_protocol_options: Vec<d::IntOperator>,
    action: Option<ActionType>,
    option: Option<OptionType<'a>>,
    log: Option<ActionType>,
    log_level: Option<d::ActionSetting<'a, ActionType>>,
    action_modifiers: Vec<ActionSetting<'a>>,
}

impl<'a> RawACLRule<'a> {
    fn new(interfaces: &'a Vec<String>) -> Self {
        Self {
            rule: d::Rule::default(),
            protocol: d::ProtocolSettingBuilder::new(),
            extended: d::ACL::default(),
            vendor: d::nftables::Vendor::default(),
            interface: Interface::new(interfaces),
            name: None,
            conntrack: false,
            ip_range: false,
            ip_protocol_options: vec![],
            action: None,
            option: None,
            log: None,
            log_level: None,
            action_modifiers: vec![],
        }
    }

    fn mapping(&mut self, item: Token<'a>) {
        match item {
            Token::Conntrack(_) => self.conntrack = true,
            Token::IPrange(_) => self.ip_range = true,
            // protocol
            Token::Protocol(v) => self.protocol.set_protocol(v),
            Token::DestinationPorts(v) => self.protocol.extend_destination_ports(v),
            Token::SourcePorts(v) => self.protocol.extend_source_ports(v),
            Token::Ports(v) => self.protocol.extend_ports(v),
            Token::Fragment(v) => self.protocol.add_fragment(v),
            Token::DSCP(v) => self.protocol.add_dscp(v),
            Token::PacketLength(v) => self.protocol.add_packet_length(v),
            Token::IPProtocolOption(v) => self.ip_protocol_options.push(v),
            Token::TCPFlags(v) => self.protocol.set_flags(v),
            Token::TTL(v) => self.protocol.add_ttl(v),
            Token::Ctorigdstport(v) => {
                self.conntrack
                    .then(|| self.protocol.extend_destination_ports(v));
            }
            Token::Ctorigsrcport(v) => {
                self.conntrack.then(|| self.protocol.extend_source_ports(v));
            }
            // action
            Token::Action(v) => self.action = Some(v),
            Token::Option(v) => self.option = Some(v),
            Token::Log(v) => self.log = Some(v),
            Token::LogLevel(v) => self.log_level = Some(v),
            Token::ActionModifier(v) => self.action_modifiers.push(v),
            Token::InterfaceIn(v) => {
                self.extended
                    .add_interface_in_vec(p::interface(v.0, v.1, &self.interface))
            }
            Token::InterfaceOut(v) => {
                self.extended
                    .add_interface_out_vec(p::interface(v.0, v.1, &self.interface))
            }
            // common
            Token::Destination(v) => self.rule.add_destination(v),
            Token::Ctorigdst(v) => {
                self.conntrack.then(|| self.rule.add_destination(v));
            }
            Token::Source(v) => self.rule.add_source(v),
            Token::Ctorigsrc(v) => {
                self.conntrack.then(|| self.rule.add_source(v));
            }

            // vendor
            Token::Ctstate(v) => self.vendor.extend_connection_states(v),
            Token::Sets(v) => self.vendor.add_set(v),

            Token::SrcRange(v) => todo!(),
            Token::DstRange(v) => todo!(),

            Token::Name(v) => self.name = Some(v),
            Token::Error(v) => debug!("Error: {:?}", v),
            Token::Space => (),
        };
    }

    fn build(mut self) -> ACLRule<'a> {
        let defaults = ACLRule::new(
            None,
            Some(d::ProtocolSetting::new(
                Some(d::Protocol::ip()),
                None,
                None,
                None,
            )),
            vec![],
            vec![],
            vec![],
            vec![],
            Some(d::ACL::new(
                vec![ActionSetting::new(d::nftables::ActionType::PASS, "")],
                vec![],
                Some(d::NormalizedAction::PASS),
                vec![],
                vec![],
                vec![],
                vec![],
            )),
            Some(d::nftables::Vendor::default()),
        );

        self.protocol
            .extend_ip_protocol_options(self.ip_protocol_options);
        let protocol = { self.protocol.build() };

        let extended = {
            action_setting(self.action, self.option).map(|v| self.extended.add_action(v));

            self.log.is_some().then(|| {
                action_setting(self.log, None).map(|v| self.extended.add_action(v));
                self.log_level
                    .or(Some(ActionSetting::new(
                        d::nftables::ActionType::LogLevel,
                        "warning",
                    )))
                    .map(|v| self.extended.add_action_modifier(v));
            });

            self.extended.extend_action_modifiers(self.action_modifiers);
            self.extended.build()
        };

        let vendor = self.vendor.build();

        protocol.map(|v| self.rule.add_protocol(v));
        extended.map(|v| self.rule.add_extended(v));
        vendor.map(|v| self.rule.add_vendor(v));

        let mut result = self.rule.build();
        result.merge(defaults);
        result
    }
}

enum Token<'a> {
    Action(ActionType),
    Log(ActionType),
    LogLevel(d::ActionSetting<'a, ActionType>),
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
    Source(d::EndpointSetting),
    Destination(d::EndpointSetting),
    IPrange(&'a str),
    SrcRange(d::IPOperator),
    DstRange(d::IPOperator),
    Conntrack(&'a str),
    Ctorigsrc(d::EndpointSetting),
    Ctorigdst(d::EndpointSetting),
    Ctorigdstport(Vec<d::IntOperator>),
    Ctorigsrcport(Vec<d::IntOperator>),
    Ctstate(Vec<d::StringOperator<'a>>),
    Sets(d::SetOperator<'a>),
    InterfaceIn((d::OperatorType, Vec<p::Interface<'a>>)),
    InterfaceOut((d::OperatorType, Vec<p::Interface<'a>>)),
}

impl<'a> Token<'a> {
    fn space(_: &'a str) -> Self {
        Token::Space
    }
}

fn _parser<'a>(
    interfaces: &'a Vec<String>,
    user_chains: &'a Vec<String>,
    input: &'a str,
) -> IResult<&'a str, RawACLRule<'a>> {
    let p1 = alt_impl!(
        Token,
        "Name" = name,
        "Action" = map(
            verify(tag_value("-j"), |value: &str| value != "LOG"
                && ActionType::from_str(value).is_ok()), // TODO выкинуть один :from_str
            |v| ActionType::from_str(v).unwrap()
        ),
        "Option" = alt((
            map(tag_value("--reject-with"), |v| OptionType::Value(v)),
            map(tag_value("-g"), |v| OptionType::Goto(v)),
            map(
                verify(tag_value("-j"), |v: &str| user_chains
                    .iter()
                    .any(|e| e == v)),
                |v| { OptionType::Jump(v) }
            ),
        )),
        "Log" = map(verify(tag_value("-j"), |value: &str| value == "LOG"), |v| {
            ActionType::from_str(v).unwrap()
        }),
        "LogLevel" = log_level,
        "ActionModifier" = ip_options,
        "Ports" = port("--ports"),
        "SourcePorts" = alt((port("--sports"), port("--sport"))),
        "DestinationPorts" = alt((port("--dports"), port("--dport"))),
        "Protocol" = protocol,
        "TCPFlags" = TSPFlags::parser,
        "TTL" = ttl,
        "DSCP" = dscp,
        "Fragment" = fragment,
        "PacketLength" = length,
        "IPProtocolOption" = ip_protocol_options,
        "Destination" = ip4_address("-d"),
        "Source" = ip4_address("-s"),
        "space" = space1,
        "Error" = unknown_part,
    );

    let parser2 = alt_impl!(
        Token,
        "IPrange" = module("iprange"),
        "SrcRange" = ip4_range_address("--srcrange"),
        "DstRange" = ip4_range_address("--dstrange"),
        "Conntrack" = module("conntrack"),
        "Ctorigsrc" = ip4_address("--ctorigsrc"),
        "Ctorigdst" = ip4_address("--ctorigdst"),
        "Ctorigdstport" = port("--ctorigdstport"),
        "Ctorigsrcport" = port("--ctorigsrcport"),
        "Ctstate" = ctstate,
        "Sets" = set,
        "InterfaceIn" = interface("-i"),
        "InterfaceOut" = interface("-o"),
    );
    fold_many1(
        alt((parser2, p1)),
        || RawACLRule::new(interfaces),
        |mut acc, item: Token| {
            acc.mapping(item);
            acc
        },
    )
    .parse(input)
}

pub fn rule<'a>(
    input: &'a str,
    interfaces: &'a Vec<String>,
    user_chains: &'a Vec<String>,
) -> IResult<&'a str, ACLRule<'a>> {
    let (remain, rule) = _parser(&interfaces, &user_chains, input)?;
    Ok((remain, rule.build()))
}
