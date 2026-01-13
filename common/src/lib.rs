use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{alpha1, u16, space1},
    combinator::{map, value},
    error::ParseError,
    multi::separated_list1,
    sequence::{pair, preceded, separated_pair},
    IResult, Parser,
};

mod ip;
pub use ip::*;

use domain as d;
use d::BuildOperatorType;

// парсеры нельзя клонировать поэтому такая
pub fn single_or_pair<'a, T, E: ParseError<&'a str>, F>(
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

pub fn single_or_pair_u16(
    arg: &'static str,
) -> impl Fn(&str) -> IResult<&str, d::SingleOrPair<u16>> {
    move |input: &str| single_or_pair(arg, u16, u16, u16).parse(input)
}

pub fn preceded_tag<'a, T, E: ParseError<&'a str>, F>(
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
    separated_list1(tag(","), f)
}

pub fn pair_sep_colon(s: &str) -> IResult<&str, d::SingleOrPair<u16>> {
    single_or_pair_u16(":").parse(s)
}

pub fn pair_sep_space(s: &str) -> IResult<&str, d::SingleOrPair<u16>> {
    single_or_pair_u16(" ").parse(s)
}

fn ttl_build(operator: d::OperatorType, value: u16) -> d::IntOperator {
    d::IntOperator::new(operator.single(), vec![value])
}

pub fn ttl<'a, E: ParseError<&'a str>, F>(f: F) -> impl Parser<&'a str, d::IntOperator, E>
where
    F: Parser<&'a str, (d::OperatorType, u16), E>,
{
    map(f, |pair| ttl_build(pair.0, pair.1))
}

fn dscp_build(value: u16) -> d::IntOperator {
    d::IntOperator::new(d::OperatorType::EQ, vec![value])
}

pub fn dscp<'a, E: ParseError<&'a str>, F>(f: F) -> impl Parser<&'a str, d::IntOperator, E>
where
    F: Parser<&'a str, u16, E>,
{
    map(f, |value| dscp_build(value))
}

pub fn protocol<'a, E: ParseError<&'a str>, F>(f: F) -> impl Parser<&'a str, d::Protocol<'a>, E>
where
    F: Parser<&'a str, (d::OperatorType, d::StringOrU16<'a>), E>,
{
    map(f, |(operator, value)| d::Protocol::new(operator, value))
}

fn port_build(operator: d::OperatorType, value: d::SingleOrPair<u16>) -> d::IntOperator {
    d::IntOperator::build(operator, value)
}

fn ports_build(
    operator: d::OperatorType,
    values: Vec<d::SingleOrPair<u16>>,
) -> Vec<d::IntOperator> {
    values
        .into_iter()
        .map(|i| port_build(operator.clone(), i))
        .collect()
}

pub fn ports<'a, E: ParseError<&'a str>, F>(f: F) -> impl Parser<&'a str, Vec<d::IntOperator>, E>
where
    F: Parser<&'a str, (d::OperatorType, Vec<d::SingleOrPair<u16>>), E>,
{
    map(f, |pair| ports_build(pair.0, pair.1))
}

pub fn port<'a, E: ParseError<&'a str>, F>(f: F) -> impl Parser<&'a str, d::IntOperator, E>
where
    F: Parser<&'a str, (d::OperatorType, d::SingleOrPair<u16>), E>,
{
    map(f, |pair| port_build(pair.0, pair.1))
}

#[cfg(test)]
mod tests {
    // !TODO
}
