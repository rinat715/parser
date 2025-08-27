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

pub fn pair_sep_colon(s: &str) -> IResult<&str, d::SingleOrPair<u16>> {
    single_or_pair_u16(":").parse(s)
}

#[cfg(test)]
mod tests {
    // !TODO
}
