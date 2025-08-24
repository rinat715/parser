use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{alpha1, u16, u8},
    combinator::{map, value},
    error::ParseError,
    multi::many_m_n,
    sequence::{pair, preceded, separated_pair, terminated, tuple},
    IResult, Parser,
};

mod ip;

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

pub fn protocol(s: &str) -> IResult<&str, d::StringOrU16> {
    let any = value(d::StringOrU16::String("ip"), alt((tag("any"), tag("ip"))));
    let string = map(alpha1, d::StringOrU16::String);
    let number = map(u16, d::StringOrU16::Number);
    alt((any, string, number)).parse(s)
}

mod tests {
    // !TODO
}
