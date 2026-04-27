use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{char, space1, u16, u8},
    combinator::{map, map_res},
    error::ParseError,
    multi::separated_list1,
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

fn _ip4(input: &str) -> IResult<&str, u8> {
    terminated(u8, char('.')).parse(input)
}

pub fn ip4(input: &str) -> IResult<&str, d::IP> {
    let parser = tuple((_ip4, _ip4, _ip4, u8));

    map(parser, |res| d::IP::new_ip4(res.0, res.1, res.2, res.3)).parse(input)
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

pub fn set<'a, E: ParseError<&'a str>, F, T>(f: F) -> impl Parser<&'a str, d::SetOperator<'a>, E>
where
    T: d::BuildOperatorType,
    F: Parser<&'a str, (T, &'a str, Vec<&'a str>), E>,
{
    map(f, |(operator, set, flags)| {
        d::SetOperator::new(operator.single(), set, flags)
    })
}

pub enum Interface<'a> {
    Value(&'a str),
    Mask(&'a str),
}

pub fn interface<'a, T>(
    operator: d::OperatorType,
    values: Vec<Interface<'a>>,
    normalizator: &T,
) -> Vec<d::StringOperator<'a>>
where
    T: d::Normalizator<Arg = &'a str, Result = Vec<&'a str>>,
{
    let mut res = vec![];
    for value in values {
        match value {
            Interface::Value(v) => res.push(d::StringOperator::new(operator.clone(), vec![v])),
            Interface::Mask(v) => {
                res.extend(
                    normalizator
                        .normalize(&v)
                        .iter()
                        .map(|v| d::StringOperator::new(operator.clone(), vec![v]))
                        .collect::<Vec<d::StringOperator>>(),
                );
            }
        }
    }
    res
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
