use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{space1, u16},
    combinator::map,
    error::ParseError,
    multi::separated_list1,
    sequence::{pair, preceded, separated_pair},
    IResult, Parser,
};

mod ip;
pub use ip::*;

use d::BuildOperatorType;
use domain as d;

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

pub fn single_int_operator<'a, E: ParseError<&'a str>, F, T>(
    f: F,
) -> impl Parser<&'a str, d::IntOperator, E>
where
    T: BuildOperatorType,
    F: Parser<&'a str, (T, u16), E>,
{
    map(f, |(operator, value)| {
        d::IntOperator::new(operator.single(), vec![value])
    })
}

pub fn dscp<'a, E: ParseError<&'a str>, F>(f: F) -> impl Parser<&'a str, d::IntOperator, E>
where
    F: Parser<&'a str, u16, E>,
{
    map(f, |value| {
        d::IntOperator::new(d::OperatorType::EQ, vec![value])
    })
}

pub fn protocol<'a, E: ParseError<&'a str>, F, T>(f: F) -> impl Parser<&'a str, d::Protocol<'a>, E>
where
    T: BuildOperatorType,
    F: Parser<&'a str, (T, d::StringOrU16<'a>), E>,
{
    map(f, |(operator, value)| d::Protocol::new(operator.single(), value))
}

pub fn many_int_operator<'a, E: ParseError<&'a str>, F, T>(
    f: F,
) -> impl Parser<&'a str, Vec<d::IntOperator>, E>
where
    T: BuildOperatorType + Clone,
    F: Parser<&'a str, (T, Vec<d::SingleOrPair<u16>>), E>,
{
    map(f, |(operator, values)| {
        values
            .into_iter()
            .map(|i| d::IntOperator::build(operator.clone(), i))
            .collect()
    })
}

pub fn int_operator<'a, E: ParseError<&'a str>, F, T>(
    f: F,
) -> impl Parser<&'a str, d::IntOperator, E>
where
    T: BuildOperatorType,
    F: Parser<&'a str, (T, d::SingleOrPair<u16>), E>,
{
    map(f, |(operator, value)| {
        d::IntOperator::build(operator, value)
    })
}

pub static TCP_FLAGS_ALL: [&str; 6] = ["SYN", "ACK", "FIN", "RST", "URG", "PSH"];

fn tcp_flags_<'a>(
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

pub fn tcp_flags<'a, E: ParseError<&'a str>, F>(
    f: F,
) -> impl Parser<&'a str, (d::StringOperator<'a>, d::StringOperator<'a>), E>
where
    F: Parser<&'a str, (d::OperatorType, (Vec<&'a str>, Vec<&'a str>)), E>,
{
    map(f, |(operator, value)| tcp_flags_(operator, value))
}

#[cfg(test)]
mod tests {
    // !TODO
}
