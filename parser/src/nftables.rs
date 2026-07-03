mod builder;

pub use builder::RawACLRule;

use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::{tag, take, take_until, take_until1},
    character::complete::{
        alpha1, alphanumeric1, hex_digit1, line_ending, newline, not_line_ending, space1, u8,
    },
    combinator::{eof, map, map_parser, not, opt, peek, recognize, rest_len, value},
    multi::{fold_many1, many1},
    sequence::{pair, preceded, separated_pair, terminated},
};

use std::{
    cell::{RefCell, RefMut},
    cmp,
    collections::BTreeMap,
    rc::Rc,
};

use crate::{
    domain::{
        self as d,
        nftables::{Chain, ChainName, DefaultAction, Table, UserChain},
    },
    nftables::builder::{
        ACLExtendedEnum, ACLPart, Address, Interface, ProtocolPart, RulePart, Token,
    },
};

use crate::{
    Context,
    parser::{self as p},
};
use crate::{
    domain::Str,
    parser::{SingleOrPairU16, preceded_tag_space, separated_by_comma},
};
use macros::alt_impl;

type Operator = d::nftables::OperatorType;
type ActionType = d::nftables::ActionType;
type ActionSetting = d::nftables::ActionSetting;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use serde_derive::Deserialize;

    #[derive(Deserialize)]
    struct TestSuit {
        input: String,
        remaining: String,
        expected: Value,
    }

    use fixtures::fixtures;
    use yaml_serde::Value;

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
        let actual = yaml_serde::to_string(&actual_obj).unwrap();
        let expected = yaml_serde::to_string(&expected_obj).unwrap();
        let file_path = path.to_string_lossy();

        assert_eq!(
            actual,
            expected,
            "{}",
            diff::Diff::new(&file_path, name, &actual, &expected)
        );
    }

    #[fixtures(["acl.yaml"])]
    #[test]
    fn test_rule(path: &std::path::Path) {
        let contents = fs::read_to_string(&path).expect("Should have been able to read the file");

        let interfaces = vec![String::from("swp1"), String::from("swp2")];
        let user_chains = vec![String::from("MY_CHAIN")];

        let context = Context::new(interfaces, user_chains);

        let ctx: Rc<RefCell<_>> = Rc::new(RefCell::new(context));

        let map: yaml_serde::Mapping = yaml_serde::from_str(&contents).unwrap();
        for (test_name, value) in map {
            let test: TestSuit = yaml_serde::from_value(value).unwrap();
            let (remaining, mut rule_str) = acl_rule_parser(&ctx)(&test.input).unwrap();
            rule_str.set_number(1);
            rule_str.set_status();
            let rule = rule_str.build();

            let test_name = test_name.as_str().unwrap();

            assert_remaining_wrap(path, &test_name, &test.remaining, remaining);
            assert_eq_wrap(path, &test_name, &rule, &test.expected)
        }
    }

    #[fixtures(["chain.yaml"])]
    #[test]
    fn test_chains<'a>(path: &std::path::Path) {
        let contents = fs::read_to_string(&path).expect("Should have been able to read the file");
        let map: yaml_serde::Mapping = yaml_serde::from_str(&contents).unwrap();
        for (test_name, value) in map {
            let test: TestSuit = yaml_serde::from_value(value).unwrap();
            let (remaining, result) = many1(alt((filter_chain, raw_chain)))
                .parse(&test.input)
                .unwrap();
            let test_name = test_name.as_str().unwrap();

            assert_remaining_wrap(path, &test_name, &test.remaining, remaining);
            assert_eq_wrap(path, &test_name, &result, &test.expected)
        }
    }

    #[fixtures(["table.yaml"])]
    #[test]
    fn test_table<'a>(path: &std::path::Path) {
        let contents = fs::read_to_string(&path).expect("Should have been able to read the file");
        let map: yaml_serde::Mapping = yaml_serde::from_str(&contents).unwrap();
        for (test_name, value) in map {
            let test: TestSuit = yaml_serde::from_value(value).unwrap();

            let interfaces = vec![String::from("swp1"), String::from("swp2")];
            let context = Context::new(interfaces, vec![]);
            let ctx: Rc<RefCell<_>> = Rc::new(RefCell::new(context));

            let (remaining, result) = table(&ctx)(&test.input).unwrap();

            let test_name = test_name.as_str().unwrap();

            assert_remaining_wrap(path, test_name, &test.remaining, remaining);
            assert_eq_wrap(path, test_name, &result, &test.expected)
        }
    }

    #[fixtures(["tables.yaml"])]
    #[test]
    fn test_tables<'a>(path: &std::path::Path) {
        let contents = fs::read_to_string(&path).expect("Should have been able to read the file");
        let map: yaml_serde::Mapping = yaml_serde::from_str(&contents).unwrap();
        for (test_name, value) in map {
            let test: TestSuit = yaml_serde::from_value(value).unwrap();
            let interfaces = vec![String::from("swp1"), String::from("swp2")];

            let context = Context::new(interfaces, vec![]);

            let ctx: Rc<RefCell<_>> = Rc::new(RefCell::new(context));

            let (remaining, result) = tables(&ctx)(&test.input).unwrap();
            let test_name = test_name.as_str().unwrap();

            assert_remaining_wrap(path, &test_name, &test.remaining, remaining);
            assert_eq_wrap(path, &test_name, &result, &test.expected)
        }
    }

    #[fixtures(["tableinner.yaml"])]
    #[test]
    fn test_table_inner<'a>(path: &std::path::Path) {
        let contents = fs::read_to_string(&path).expect("Should have been able to read the file");
        let map: yaml_serde::Mapping = yaml_serde::from_str(&contents).unwrap();
        for (test_name, value) in map {
            let test: TestSuit = yaml_serde::from_value(value).unwrap();
            let (remaining, result) = table_raw(&test.input).unwrap();
            let test_name = test_name.as_str().unwrap();

            assert_remaining_wrap(path, &test_name, &test.remaining, remaining);
            assert_eq_wrap(path, &test_name, &result, &test.expected)
        }
    }

    #[fixtures(["wrap_error_line.yaml"])]
    #[test]
    fn test_wrap_error_line<'a>(path: &std::path::Path) {
        let contents = fs::read_to_string(&path).expect("Should have been able to read the file");
        let map: yaml_serde::Mapping = yaml_serde::from_str(&contents).unwrap();
        for (test_name, value) in map {
            let test: TestSuit = yaml_serde::from_value(value).unwrap();
            let (remaining, result) =
                crate::parser::wrap_error_line(tag::<&str, &str, nom::error::Error<&str>>("a"))
                    .parse(&test.input)
                    .unwrap();
            let test_name = test_name.as_str().unwrap();

            assert_remaining_wrap(path, &test_name, &test.remaining, remaining);
            assert_eq_wrap(path, &test_name, &result, &test.expected)
        }
    }

    #[test]
    #[should_panic(
        expected = "called `Result::unwrap()` on an `Err` value: Error(Error { input: \"\", code: TakeUntil })"
    )]
    fn test_wrap_error_line_error() {
        crate::parser::wrap_error_line(tag::<&str, &str, nom::error::Error<&str>>("a"))
            .parse("")
            .unwrap();
    }

    #[test]
    fn test_chain() {
        let (rem, res) = filter_chain(":INPUT ACCEPT [0:0]\n").unwrap();
        assert_eq!("", rem);
        assert_eq!("INPUT", res.0);
        assert_eq!("ACCEPT", res.1);
    }

    #[test]
    fn test_user_chain() {
        let (rem, res) = user_chain(":my_chain - [0:0]\n").unwrap();
        assert_eq!("", rem);
        assert_eq!("my_chain", res.0);
        assert_eq!("return", res.1);
    }

    #[test]
    fn test_dscp() {
        let (rem, res) = dscp("--dscp 0x20").unwrap();
        assert_eq!("", rem);
        assert_eq!(
            "Operator: eq\nValues:\n- 32\n",
            yaml_serde::to_string(&res).unwrap()
        )
    }

    #[test]
    fn test_length() {
        let (rem, res) = length("--length 300").unwrap();
        assert_eq!("", rem);
        assert_eq!(
            "Operator: eq\nValues:\n- 300\n",
            yaml_serde::to_string(&res).unwrap()
        )
    }

    #[test]
    fn test_reject_with() {
        let (rem, res) = tag_value("--reject-with")("--reject-with tcp-reset").unwrap();
        assert_eq!("", rem);
        assert_eq!("tcp-reset", res)
    }

    #[test]
    fn test_interface() {
        let (rem, res) = interface("-i")("-i eth1,mgmt").unwrap();
        assert_eq!("", rem);

        if let Interface::Value(v) = res.1[0] {
            assert_eq!(v, "eth1")
        }

        if let Interface::Value(v) = res.1[1] {
            assert_eq!(v, "mgmt")
        }
    }

    #[test]
    fn test_port() {
        let (rem, res) = port("--sports")("--sports 300:400").unwrap();
        assert_eq!("", rem);

        assert_eq!(
            "Operator: range\nValues:\n- 300\n- 400\n",
            yaml_serde::to_string(&res[0]).unwrap()
        );

        let (rem, res) = port("--dports")("--dports 22,23").unwrap();
        assert_eq!("", rem);

        let expected = r#"- Operator: eq
  Values:
  - 22
- Operator: eq
  Values:
  - 23
"#;

        let actual = yaml_serde::to_string(&res).unwrap();

        assert_eq!(
            expected,
            actual,
            "{}",
            diff::Diff::new("None", "test_port case2", &actual, &expected)
        )
    }

    #[test]
    fn test_tcp_protocol() {
        let (rem, (operator, protocol_type)) = protocol("-p tcp").unwrap();
        assert_eq!("", rem);

        assert!(operator.0.is_none());

        if let d::ProtocolType::TCP = protocol_type {
            assert!(true)
        } else {
            assert!(false, "TCP needed")
        }
    }

    #[test]
    fn test_ttl() {
        let (rem, res) = ttl("--ttl-", ttl_operator)("--ttl-gt 200").unwrap();
        assert_eq!("", rem);
        let expected = r#"Operator: gt
Values:
- 200
"#;

        let actual = yaml_serde::to_string(&res).unwrap();

        assert_eq!(
            expected,
            actual,
            "{}",
            diff::Diff::new("None", "test_ttl", &actual, &expected)
        )
    }

    #[test]
    fn test_tcp_flags() {
        let (rem, res) = tcp_flags("--tcp-flags FIN,SYN,ACK ACK").unwrap();
        assert_eq!("", rem);
        let expected = r#"- Operator: neq
  Values:
  - - FIN
    - SYN
- Operator: eq
  Values:
  - - ACK
"#;

        let actual = yaml_serde::to_string(&res).unwrap();

        assert_eq!(
            expected,
            actual,
            "{}",
            diff::Diff::new("None", "test_tcp_flags", &actual, &expected)
        )
    }

    #[test]
    fn test_range_ip_address() {
        let (rem, res) =
            ip4_address("--src-range")("--src-range 192.168.0.2-192.168.0.100").unwrap();
        assert_eq!("", rem);

        let expected = r#"Operator: range
Values:
- Address:
    Address: 192.168.0.2
    Version: 4
  NetworkID:
    Address: 192.168.0.2
    Version: 4
  Prefix: 32
- Address:
    Address: 192.168.0.100
    Version: 4
  NetworkID:
    Address: 192.168.0.100
    Version: 4
  Prefix: 32
"#;
        let actual = yaml_serde::to_string(&res).unwrap();

        assert_eq!(
            expected,
            actual,
            "{}",
            diff::Diff::new("None", "test_range_ip_address", &actual, &expected)
        )
    }

    #[test]
    fn test_storigsrc() {
        let (rem, res) = ip4_address("--ctorigsrc")("--ctorigsrc 10.10.140.3").unwrap();
        assert_eq!("", rem);
        let expected = r#"Operator: eq
Values:
- Address:
    Address: 10.10.140.3
    Version: 4
  NetworkID:
    Address: 10.10.140.3
    Version: 4
  Prefix: 32
"#;
        let actual = yaml_serde::to_string(&res).unwrap();

        assert_eq!(
            expected,
            actual,
            "{}",
            diff::Diff::new("None", "test_storigsrc", &actual, &expected)
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
    // лучше выкидывать все непробельные символы

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

fn tag_value<'a>(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded_tag_space(arg, until_eof).parse(input)
}

fn unknown_part(input: &str) -> IResult<&str, &str> {
    not(alt((eof, line_ending))).parse(input)?;

    recognize(pair(opt(alt((tag(" -"), tag(" !")))), until_eof)).parse(input)
}

fn operator(s: &str) -> IResult<&str, Operator> {
    let operator_ = value(d::nftables::EXCLAMATION, tag("!"));
    let parser = opt(terminated(operator_, space1));

    map(parser, Operator::new).parse(s)
}

// https://ipset.netfilter.org/iptables-extensions.man.html

// --ttl-eq
// --ttl-gt
// --ttl-lt
fn ttl_operator(s: &str) -> IResult<&str, d::TTLOperatorType> {
    alt((
        value(d::TTLOperatorType::EQ, tag("eq")),
        value(d::TTLOperatorType::GT, tag("gt")),
        value(d::TTLOperatorType::LT, tag("lt")),
    ))
    .parse(s)
}

fn ttl<F>(
    arg: &'static str,
    operator: F,
) -> impl Fn(&str) -> IResult<&str, d::TTL, nom::error::Error<&str>>
where
    F: for<'a> Parser<&'a str, Output = d::TTLOperatorType, Error = nom::error::Error<&'a str>>
        + Clone,
{
    move |input: &str| {
        let ttl_parser = separated_pair(preceded(tag(arg), operator.clone()), space1, u8);

        p::ttl(ttl_parser).parse(input)
    }
}

// -f ! -f
fn fragment(s: &str) -> IResult<&str, d::Fragment> {
    map(pair(map(operator, d::Fragment::new), tag("-f")), |pair| {
        pair.0
    })
    .parse(s)
}

// --dscp 0x20
fn dscp(s: &str) -> IResult<&str, d::DSCP> {
    let parser = map(
        preceded_tag_space("--dscp", preceded(tag("0x"), hex_digit1)),
        |v| (d::DSCPOperatorType::EQ, u8::from_str_radix(v, 16).unwrap()),
    );

    p::dscp(parser).parse(s)
}

// --length 300
// --length 300:301
// --length !300:301
fn length(s: &str) -> IResult<&str, d::PacketLength> {
    let value = pair(operator, SingleOrPairU16::sep_colon);

    p::packet_length(preceded_tag_space("--length", value)).parse(s)
}

fn ip_protocol_options(s: &str) -> IResult<&str, d::IPProtocolOptions> {
    // [!] --rr  = 7
    // [!] --ts = 68
    // [!] --ra = 148
    let rr = map(pair(operator, tag("--rr")), |(operator, _)| {
        d::IPProtocolOptions::record_route(operator)
    });
    let ra = map(pair(operator, tag("--ra")), |(operator, _)| {
        d::IPProtocolOptions::router_alert(operator)
    });
    let ts = map(pair(operator, tag("--ts")), |(operator, _)| {
        d::IPProtocolOptions::timestamp(operator)
    });

    let ssrr = value(d::IPProtocolOptions::StrictSourceRouting, tag("--ssrr"));
    let lsrss = value(d::IPProtocolOptions::LooseSourceRouting, tag("--lsrr"));
    let no_srr = value(d::IPProtocolOptions::NoSourceRouting, tag("--no-srr"));
    let any_opt = value(d::IPProtocolOptions::ANY, tag("--any-opt"));

    alt((rr, ra, ts, ssrr, lsrss, no_srr, any_opt)).parse(s)
}

//  --sport 500:600 --dport 45
// ! --ports 50,300:400
// --ports 50
fn port(arg: &'static str) -> impl Fn(&str) -> IResult<&str, Vec<d::PortOperator>> {
    move |input: &str| {
        let port = map(SingleOrPairU16::sep_colon, |v| vec![v]);
        let ports = separated_by_comma(SingleOrPairU16::sep_colon);

        p::port_many(pair(operator, preceded_tag_space(arg, alt((ports, port))))).parse(input)
    }
}

//  ! -s 192.168.0.1/32
//  -A OUTPUT -s 192.168.0.1/32 -d 100.100.100.0/24 p icmp -m iprange --srcrange 192.168.0.2-192.168.0.100 ! --dstrange 100.100.100.10-100.100.100.200
// -m conntrack --ctorigsrc 10.10.140.3 --ctorigdst 10.0.0.0/8 ! --ctorigdstport 443
fn ip4_address(arg: &'static str) -> impl Fn(&str) -> IResult<&str, d::IPOperator> {
    move |input: &str| {
        let network = map(pair(terminated(p::ip4, tag("/")), u8), |v| {
            Address::Network(v)
        });
        // --ctorigsrc 10.10.140.3 prefix равен 32
        let ip = map(p::ip4, Address::IP);
        // 192.168.0.2-192.168.0.100
        let range_ip = map(separated_pair(p::ip4, tag("-"), p::ip4), |v| {
            Address::Range(v)
        });

        map(
            pair(
                operator,
                preceded_tag_space(arg, alt((range_ip, network, ip))),
            ),
            |(operator, address)| address.ip_operator(operator),
        )
        .parse(input)
    }
}

pub fn tcp_flag_item(s: &str) -> IResult<&str, Vec<d::Flag>> {
    let flag = alt((
        value(d::Flag::SYN, tag("SYN")),
        value(d::Flag::ACK, tag("ACK")),
        value(d::Flag::FIN, tag("FIN")),
        value(d::Flag::RST, tag("RST")),
        value(d::Flag::URG, tag("URG")),
        value(d::Flag::PSH, tag("PSH")),
    ));

    let none = value(vec![], tag("NONE"));
    let all = value(Vec::from(d::TCP_FLAGS_ALL.clone()), tag("ALL"));

    alt((separated_by_comma(flag), none, all)).parse(s)
}

fn tcp_flags(s: &str) -> IResult<&str, (d::FlagOperator, d::FlagOperator)> {
    p::tcp_flags(pair(
        operator,
        preceded_tag_space(
            "--tcp-flags",
            separated_pair(tcp_flag_item, space1, tcp_flag_item),
        ),
    ))
    .parse(s)
}

fn protocol<'a>(s: &'_ str) -> IResult<&'_ str, (Operator, d::ProtocolType)> {
    let protocol = alt((
        value(d::ProtocolType::from("ip"), alt((tag("0"), tag("all")))),
        map(alpha1, d::ProtocolType::from),
        map(u8, d::ProtocolType::from),
    ));

    pair(operator, preceded_tag_space("-p", protocol)).parse(s)
}

fn log_options(s: &str) -> IResult<&str, ActionSetting> {
    let tag_parser = alt((
        value(ActionType::LogTCPSequence, tag("--log-tcp-sequence")),
        value(ActionType::LogTCPOptions, tag("--log-tcp-options")),
        value(ActionType::LogIPOptions, tag("--log-ip-options")),
    ));

    let value_parser = value(ActionType::LogPrefix, tag("--log-prefix"));

    alt((
        map(tag_parser, |v| d::ActionSetting::new(v, None)),
        map(
            separated_pair(value_parser, space1, until_eof),
            |(action, option)| ActionSetting::new(action, Some(Str::new(option))),
        ),
    ))
    .parse(s)
}

fn log_level(s: &str) -> IResult<&str, ActionSetting> {
    let value_parser = value(ActionType::LogLevel, tag("--log-level"));

    map(
        separated_pair(value_parser, space1, until_eof),
        |(action, option)| ActionSetting::new(action, Some(Str::new(option))),
    )
    .parse(s)
}

// --ctstate INVALID,RELATED,SNAT
// ! --ctstate INVALID,RELATED,SNAT
fn ctstate(s: &str) -> IResult<&str, Vec<d::StringOperator>> {
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

// [!] --match-set setname flag1[,flag2[,...,flagn]]
// --match-set test src,dst
// ! --match-set test src,dst
fn set(s: &str) -> IResult<&str, d::SetOperator> {
    let sets = map(
        alt((
            tag("dst"),
            tag("src"),
            tag("srcport"),
            tag("dstport"),
            tag("iniface"),
            tag("outiface"),
        )),
        Str::new,
    );
    let parser = map(
        (
            operator,
            preceded_tag_space("--match-set", take_until(" ")),
            space1,
            separated_by_comma(sets),
        ),
        |res| (res.0, res.1, res.3),
    );

    p::set(parser).parse(s)
}

// -i swp+
// -o swp1
// ! -i swp3,swp4
// eth0,mgmt

fn interface(arg: &'static str) -> impl Fn(&str) -> IResult<&str, (bool, Vec<Interface>)> {
    move |input: &str| {
        let mask_parser = map(terminated(alphanumeric1, tag("+")), Interface::Mask);
        let value_parser = map(alphanumeric1, Interface::Value);

        let parser = alt((mask_parser, value_parser));

        pair(
            map(operator, |v| v.into()),
            preceded_tag_space(arg, separated_by_comma(parser)),
        )
        .parse(input)
    }
}

fn protocol_setting(input: &str) -> IResult<&str, ProtocolPart<Operator>> {
    type PROTOCOL = ProtocolPart<Operator>; // TODO fix alt_impl full path
    alt_impl!(
        PROTOCOL,
        "Ports" = port("--ports"),
        "SourcePorts" = alt((port("--sports"), port("--sport"), port("--ctorigsrcport"))),
        "DestinationPorts" = alt((port("--dports"), port("--dport"), port("--ctorigdstport"))),
        "Protocol" = protocol,
        "TCPFlags" = tcp_flags,
        "TTL" = ttl("--ttl-", ttl_operator),
        "DSCP" = dscp,
        "Fragment" = fragment,
        "PacketLength" = length,
        "IPProtocolOption" = ip_protocol_options,
    )
    .parse(input)
}

fn acl_parser<'a>(input: &'a str) -> IResult<&'a str, ACLPart<'a>> {
    alt_impl!(
        ACLPart,
        "Jump" = tag_value("-j"),
        "Goto" = tag_value("-g"),
        "RejectWith" = tag_value("--reject-with"),
        "LogLevel" = log_level,
        "ActionModifier" = log_options,
        "InterfaceIn" = interface("-i"),
        "InterfaceOut" = interface("-o"),
    )
    .parse(input)
}

fn acl_extended_parser(input: &str) -> IResult<&str, ACLExtendedEnum> {
    alt_impl!(ACLExtendedEnum, "Ctstate" = ctstate, "Sets" = set,).parse(input)
}

fn base_parser(input: &str) -> IResult<&str, RulePart> {
    let dst = alt((
        ip4_address("-d"),
        ip4_address("--dst-range"),
        ip4_address("--ctorigdst"),
    ));
    let scr = alt((
        ip4_address("-s"),
        ip4_address("--src-range"),
        ip4_address("--ctorigsrc"),
    ));

    alt_impl!(RulePart, "Destination" = dst, "Source" = scr,).parse(input)
}

fn token<'a>(input: &'a str) -> IResult<&'a str, Token<'a>> {
    alt_impl!(
        Token,
        "Protocol" = protocol_setting,
        "Base" = base_parser,
        "ACL" = acl_parser,
        "ACLExtended" = acl_extended_parser,
        "space" = space1,
        "Error" = unknown_part,
    )
    .parse(input)
}

/*
     default_chains_map = dict(
        raw={'PREROUTING', 'OUTPUT'},
        filter={'INPUT', 'OUTPUT', 'FORWARD'},
        mangle={'INPUT', 'OUTPUT', 'FORWARD', 'POSTROUTING', 'PREROUTING'},
             security={'INPUT', 'OUTPUT', 'FORWARD'}
    )

*/

// еще один вариант решения проблемы того что нельзя скопировать парсер
macro_rules! chain_m {
    ($name:tt, $parser:expr) => {
        fn $name(input: &str) -> IResult<&str, (ChainName, DefaultAction)> {
            let (remain, result) = (
                tag(":"),
                $parser,
                space1,
                map(alpha1, |v| Str::new(v)),
                space1,
                take_until("\n"),
                newline,
            )
                .parse(input)?;
            Ok((remain, (result.1, result.3)))
        }
    };
}

macro_rules! fold_chain_m {
    ($name:tt, $parser:expr) => {
        fn $name(input: &str) -> IResult<&str, BTreeMap<Str, Chain>> {
            fold_many1(
                $parser,
                BTreeMap::new,
                |mut acc: BTreeMap<Str, Chain>, (chain_name, default_action)| {
                    acc.insert(chain_name.clone(), Chain::new(chain_name, default_action));
                    acc
                },
            )
            .parse(input)
        }
    };
}

macro_rules! table_m {
    ($name:ident, $tag:literal, $parser:expr) => {
        fn $name(input: &str) -> IResult<&str, (Table, &str)> {
            let name = map(
                p::terminated_by_newline(preceded(tag("*"), tag($tag))),
                |v| Table::new(v),
            );
            let commit = (tag("COMMIT"), opt(newline));

            let (remain, (mut table, body)) =
                terminated((name, take_until("COMMIT")), commit).parse(input)?;

            let (body, filter_chain_map) = $parser(body)?;

            table.set_chain_map(filter_chain_map);

            Ok((remain, (table, body)))
        }
    };
}

chain_m!(
    raw_chain,
    map(alt((tag("PREROUTING"), tag("OUTPUT"))), |v| { Str::new(v) })
);

fold_chain_m!(fold_raw_chain, raw_chain);

chain_m!(
    filter_chain,
    map(alt((tag("INPUT"), tag("OUTPUT"), tag("FORWARD"))), |v| {
        Str::new(v)
    })
);

fold_chain_m!(fold_filter_chain, filter_chain);

chain_m!(
    mangle_chain,
    map(
        alt((
            tag("INPUT"),
            tag("OUTPUT"),
            tag("FORWARD"),
            tag("POSTROUTING"),
            tag("PREROUTING")
        )),
        |v| { Str::new(v) }
    )
);

fold_chain_m!(fold_mangle_chain, mangle_chain);

//    nat={'POSTROUTING', 'PREROUTING', 'OUTPUT', 'INPUT'},
chain_m!(
    nat_chain,
    map(
        alt((
            tag("POSTROUTING"),
            tag("PREROUTING"),
            tag("OUTPUT"),
            tag("INPUT")
        )),
        |v| { Str::new(v) }
    )
);

fn user_chain(s: &str) -> IResult<&str, (UserChain, DefaultAction)> {
    let (remain, result) = (
        tag(":"),
        take_until(" "),
        space1,
        map(opt(alpha1), |v| v.unwrap_or("return")),
        take_until("\n"),
        newline,
    )
        .parse(s)?;
    Ok((remain, (Str::new(result.1), Str::new(result.3))))
}

table_m!(table_raw, "raw", fold_raw_chain);
table_m!(table_filter, "filter", fold_filter_chain);
table_m!(table_mangle, "mangle", fold_mangle_chain);

pub fn fold_user_chain(input: &str) -> IResult<&str, Vec<(UserChain, DefaultAction)>> {
    let mut user_chains = map(opt(many1(user_chain)), |v| v.unwrap_or_default());

    user_chains.parse(input)
}

fn table<'a>(ctx: &'a Rc<RefCell<Context>>) -> impl FnMut(&'a str) -> IResult<&'a str, Table> {
    move |input: &str| {
        let (remain, (mut table, body)) =
            alt((table_raw, table_filter, table_mangle)).parse(input)?;

        let (body, user_chains) = fold_user_chain(body)?;

        let user_chain_names = table.process_user_chain(user_chains);

        let mut mut_ctx: RefMut<'_, _> = ctx.borrow_mut();
        mut_ctx.set(user_chain_names);

        drop(mut_ctx);

        let parser = p::wrap_error_line(acl_rule_parser(ctx));

        let (_, rules) = many1(parser).parse(body)?;

        table.process_ruls(rules);

        Ok((remain, table))
    }
}

fn acl_rule_parser<'a>(
    ctx: &'a Rc<RefCell<Context>>,
) -> impl Fn(&'a str) -> IResult<&'a str, RawACLRule<'a>> {
    move |s: &str| {
        let (remain, row) = p::terminated_by_newline(take_until1("\n")).parse(s)?;

        let (options, chain) = tag_value("-A").parse(row)?;

        let mut rule_parser = fold_many1(
            token,
            || RawACLRule::new(ctx, row, chain),
            |mut acc, item: Token| {
                acc.mapping(item);
                acc
            },
        );

        let (_, rule) = rule_parser.parse(options)?;
        Ok((remain, rule))
    }
}

pub fn tables<'a>(
    ctx: &'a Rc<RefCell<Context>>,
) -> impl Fn(&'a str) -> IResult<&'a str, Vec<Table>> {
    move |input: &str| {
        let parser = p::wrap_error_line(table(ctx));

        let (remain, result) = many1(parser).parse(input)?;
        let mut tables = Vec::new();
        for item in result {
            match item {
                d::Value::Value(v) => tables.push(v),
                d::Value::Error(v) => println!("Error table part {}", v.as_str()),
            }
        }
        Ok((remain, tables))
    }
}
