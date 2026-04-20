use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{char, hex_digit1, space1, u16, u8},
    combinator::{map, map_res},
    error::ParseError,
    multi::{fold_many1, separated_list1},
    sequence::{pair, preceded, separated_pair, terminated, tuple},
    IResult, Parser,
};

use crate::domain::{self as d, IntOperatorBuilder, StringOperatorBuilder};

// парсеры нельзя клонировать поэтому такая
fn single_or_pair<'a, T, E: ParseError<&'a str>, F>(
    sep: &'static str,
    f1: F,
    f2: F,
    f3: F,
) -> impl Parser<&'a str, d::SingleOrPair<T>, E>
where
    F: Parser<&'a str, T, E>,
{
    alt((
        map(f1, |value| d::SingleOrPair::Single(value)),
        map(separated_pair(f2, tag(sep), f3), |(f, s)| {
            d::SingleOrPair::Pair(f, s)
        }),
    ))
}

pub struct SingleOrPairU16;
impl SingleOrPairU16 {
    fn parser(arg: &'static str) -> impl Fn(&str) -> IResult<&str, d::SingleOrPair<u16>> {
        move |input: &str| single_or_pair(arg, u16, u16, u16).parse(input)
    }

    pub fn sep_colon(s: &str) -> IResult<&str, d::SingleOrPair<u16>> {
        Self::parser(":").parse(s)
    }
}

pub fn preceded_tag_space<'a, T, E: ParseError<&'a str>, F>(
    arg: &'static str,
    f: F,
) -> impl Parser<&'a str, T, E>
where
    F: Parser<&'a str, T, E>,
{
    preceded(pair(tag(arg), space1), f)
}

pub fn separated_by_comma<'a, T, E: ParseError<&'a str>, F>(f: F) -> impl Parser<&'a str, Vec<T>, E>
where
    F: Parser<&'a str, T, E>,
{
    separated_list1(tag(","), f) // TODO аллоцириет лишний вектор заменить на fold_many1
}

const LONGEST_IPV6_ADDR: &str = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"; // из std net

fn _ip4(input: &str) -> IResult<&str, u8> {
    terminated(u8, char('.')).parse(input)
}

pub fn ip4(input: &str) -> IResult<&str, d::IP> {
    let parser = tuple((_ip4, _ip4, _ip4, u8));

    map(parser, |res| d::IP::new_ip4(res.0, res.1, res.2, res.3)).parse(input)
}

fn ip6(input: &str) -> IResult<&str, d::IP> {
    let item_parser = alt((hex_digit1, tag(":")));

    let parser = fold_many1(
        item_parser,
        || String::with_capacity(LONGEST_IPV6_ADDR.len()),
        |mut acc: String, item| {
            acc.push_str(item);
            acc
        },
    );

    map_res(parser, |r| d::IP::parse_ip6(&r)).parse(input) // MapRes а AddrParseError подавится
}

pub fn ip_parser(input: &str) -> IResult<&str, d::IP> {
    alt((ip4, ip6)).parse(input)
}

pub fn ip4_adresss(input: &str) -> IResult<&str, d::IPAddress> {
    map_res(pair(terminated(ip4, tag("/")), u8), |(ip, prefix)| {
        d::IPAddress::new(ip.into(), prefix)
    })
    .parse(input)
}

pub fn protocol<'a, E: ParseError<&'a str>, F, T>(f: F) -> impl Parser<&'a str, d::Protocol<'a>, E>
where
    T: d::BuildOperatorType,
    F: Parser<&'a str, (T, d::StringOrU16<'a>), E>,
{
    map(f, |(operator, value)| {
        d::Protocol::new(operator.single(), value)
    })
}

pub fn tcp_flags<'a, E: ParseError<&'a str>, F, T>(
    f: F,
) -> impl Parser<&'a str, (d::StringOperator<'a>, d::StringOperator<'a>), E>
where
    T: d::BuildOperatorType,
    F: Parser<&'a str, (T, (Vec<&'a str>, Vec<&'a str>)), E>,
{
    map(f, |(operator, value)| {
        d::tcp_flags(operator.single(), value)
    })
}

pub fn dscp<'a, E: ParseError<&'a str>, F>(f: F) -> impl Parser<&'a str, d::IntOperator, E>
where
    F: Parser<&'a str, u16, E>,
{
    map(f, |value| {
        IntOperatorBuilder::new(d::OperatorType::EQ).from_value(value)
    })
}

pub fn ctstate<'a, E: ParseError<&'a str>, F, T>(
    f: F,
) -> impl Parser<&'a str, Vec<d::StringOperator<'a>>, E>
where
    T: d::BuildOperatorType,
    F: Parser<&'a str, (T, Vec<&'a str>), E>,
{
    map(f, |(operator, values)| {
        let builder = StringOperatorBuilder::new(operator.single());
        values.iter().map(|v| builder.from_value(v)).collect()
    })
}

pub fn set<'a, E: ParseError<&'a str>, F, T>(
    f: F,
) -> impl Parser<&'a str, d::SetOperator<'a>, E>
where
    T: d::BuildOperatorType,
    F: Parser<&'a str, (T, &'a str, Vec<&'a str>), E>,
{
    map(f, |(operator, set, flags)| {
        d::SetOperator::new(operator.single(), set, flags)
    })
}


pub struct IntOperator;
impl IntOperator {
    pub fn parser1<'a, E: ParseError<&'a str>, F>(f: F) -> impl Parser<&'a str, d::IntOperator, E>
    where
        F: Parser<&'a str, (d::OperatorType, u16), E>,
    {
        map(f, |(operator, value)| {
            d::IntOperator::new(operator, vec![value])
        })
    }

    pub fn parser<'a, E: ParseError<&'a str>, F, T>(f: F) -> impl Parser<&'a str, d::IntOperator, E>
    where
        T: d::BuildOperatorType,
        F: Parser<&'a str, (T, d::SingleOrPair<u16>), E>,
    {
        map(f, |(operator, value)| {
            d::IntOperatorBuilder::from_build_operator_type(operator, value)
        })
    }

    pub fn parser_many<'a, E: ParseError<&'a str>, F, T>(
        f: F,
    ) -> impl Parser<&'a str, Vec<d::IntOperator>, E>
    where
        T: d::BuildOperatorType + Clone,
        F: Parser<&'a str, (T, Vec<d::SingleOrPair<u16>>), E>,
    {
        map(f, |(operator, values)| {
            values
                .into_iter()
                .map(|i| d::IntOperatorBuilder::from_build_operator_type(operator.clone(), i))
                .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4() {
        let (remain, res) = ip_parser("127.0.0.1").unwrap();
        assert_eq!(remain, "");
        assert_eq!(res, d::IP::new_ip4(127, 0, 0, 1));

        let (remain, res) = ip_parser("169.254.50.30").unwrap();
        assert_eq!(remain, "");
        assert_eq!(res, d::IP::new_ip4(169, 254, 50, 30));
    }

    #[test]
    fn test_ipv6() {
        let (remain, res) = ip_parser("123::250:56ff:fea6:430e").unwrap();
        assert_eq!(remain, "");
        assert_eq!(
            res,
            d::IP::new_ip6(0x123, 0, 0, 0, 0x250, 0x56ff, 0xfea6, 0x430e)
        );

        let (remain, res) = ip_parser("::1 dfdfdf").unwrap();
        assert_eq!(remain, " dfdfdf");
        assert_eq!(res, d::IP::new_ip6(0, 0, 0, 0, 0, 0, 0, 0x1));

        let (remain, res) = ip_parser("2001:d00::").unwrap();
        assert_eq!(remain, "");
        assert_eq!(res, d::IP::new_ip6(0x2001, 0xd00, 0, 0, 0, 0, 0, 0));

        let result = ip_parser(":");

        assert_eq!(
            result,
            Err(nom::Err::Error(nom::error::Error::new(
                ":",
                nom::error::ErrorKind::MapRes
            )))
        );

        let result = ip_parser("Z");

        assert_eq!(
            result,
            Err(nom::Err::Error(nom::error::Error::new(
                "Z",
                nom::error::ErrorKind::Many1
            )))
        );

        let result = ip_parser("");

        assert_eq!(
            result,
            Err(nom::Err::Error(nom::error::Error::new(
                "",
                nom::error::ErrorKind::Many1
            )))
        );
    }

    #[test]
    fn test_ip4_adresss() {
        let (remain, res) = ip4_adresss("192.168.0.1/32").unwrap();
        assert_eq!(remain, "");
        assert_eq!(
            "Prefix = 32

[Address]
Address = \"192.168.0.1\"
Version = 4

[NetworkID]
Address = \"192.168.0.1\"
Version = 4
",
            toml::to_string(&res).unwrap()
        )
    }
}
