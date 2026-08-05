use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::tag,
    character::complete::{char, newline, space1, u8, u16},
    combinator::map,
    error::ParseError,
    multi::separated_list1,
    sequence::{pair, preceded, separated_pair, terminated},
};

use nom::bytes::complete::take_until1;

use crate::{builder::StringOperatorBuilder, domain::{self as d, Str, }};

fn single_or_pair<'a, T, E: ParseError<&'a str>, F>(
    sep: &'static str,
    f: F,
) -> impl Parser<&'a str, Output = d::Tuple<T>, Error = E>
where
    F: Parser<&'a str, Output = T, Error = E> + Copy,
{
    alt((
        map(separated_pair(f, tag(sep), f), |(f, s)| {
            d::Tuple::Pair(f, s)
        }),
        map(f, |value| d::Tuple::Single(value)),
    ))
}

pub struct SingleOrPairU16;
impl SingleOrPairU16 {
    fn parser(arg: &'static str) -> impl Fn(&str) -> IResult<&str, d::Tuple<u16>> {
        move |input: &str| single_or_pair(arg, u16).parse(input)
    }

    pub fn sep_colon(s: &str) -> IResult<&str, d::Tuple<u16>> {
        Self::parser(":").parse(s)
    }

    pub fn sep_dash(s: &str) -> IResult<&str, d::Tuple<u16>> {
        Self::parser("-").parse(s)
    }
}

pub fn preceded_tag_space<'a, T, E: ParseError<&'a str>, F>(
    arg: &'static str,
    f: F,
) -> impl Parser<&'a str, Output = T, Error = E>
where
    F: Parser<&'a str, Output = T, Error = E>,
{
    preceded(pair(tag(arg), space1), f)
}

pub fn wrap_error_line<'a, T, E: ParseError<&'a str>, F>(
    f: F,
) -> impl Parser<&'a str, Output = d::Value<T>, Error = E>
where
    F: Parser<&'a str, Output = T, Error = E>,
{
    let err = map(terminated_by_newline(take_until1("\n")), |v| {
        d::Value::Error(Str::new(v))
    });

    let new_line = map(newline, |_| d::Value::Error(Str::new_static("NEWLINE")));

    let value = map(f, |v| d::Value::Value(v));
    alt((value, err.or(new_line)))
}

pub fn separated_by_comma<'a, T, E: ParseError<&'a str>, F>(
    f: F,
) -> impl Parser<&'a str, Output = Vec<T>, Error = E>
where
    F: Parser<&'a str, Output = T, Error = E>,
{
    separated_list1(tag(","), f) // TODO аллоцириет лишний вектор заменить на fold_many1
}

pub fn terminated_by_newline<'a, F, T, E: ParseError<&'a str>>(
    f: F,
) -> impl Parser<&'a str, Output = T, Error = E>
where
    F: Parser<&'a str, Output = T, Error = E>,
{
    terminated(f, newline)
}

fn _ip4(input: &str) -> IResult<&str, u8> {
    terminated(u8, char('.')).parse(input)
}

pub fn ip4(input: &str) -> IResult<&str, d::IP> {
    map((_ip4, _ip4, _ip4, u8), |res| {
        d::IP::new_ip4(res.0, res.1, res.2, res.3)
    })
    .parse(input)
}

pub fn tcp_flags<'a, E: ParseError<&'a str>, F, T>(
    f: F,
) -> impl Parser<&'a str, Output = (d::FlagOperator, d::FlagOperator), Error = E>
where
    T: Into<bool>,
    F: Parser<&'a str, Output = (T, (Vec<d::Flag>, Vec<d::Flag>)), Error = E>,
{
    map(f, |(operator, (f, s))| {
        let values = {
            if operator.into() {
                f.into_iter().filter(|x| !s.contains(x)).collect()
            } else {
                d::TCP_FLAGS_ALL
                    .clone()
                    .into_iter()
                    .filter(|x| !f.contains(x))
                    .collect()
            }
        };
        (
            d::FlagOperator::new(false, values),
            d::FlagOperator::new(true, s),
        )
    })
}

pub fn ctstate<'a, E: ParseError<&'a str>, F, T>(
    f: F,
) -> impl Parser<&'a str, Output = Vec<d::StringOperator>, Error = E>
where
    T: Into<d::generic::Bool>,
    F: Parser<&'a str, Output = (T, Vec<&'a str>), Error = E>,
{
    map(f, |(operator, values)| {
        let builder = StringOperatorBuilder::new(operator);
        values.iter().map(|v| builder.from_value(v)).collect()
    })
}

pub fn set<'a, E: ParseError<&'a str>, F, T>(
    f: F,
) -> impl Parser<&'a str, Output = d::SetOperator, Error = E>
where
    T: Into<d::generic::Bool>,
    F: Parser<&'a str, Output = (T, &'a str, Vec<Str>), Error = E>,
{
    map(f, |(operator, set, flags)| {
        d::SetOperator::new(operator, set, flags)
    })
}

pub fn port_many<'a, E: ParseError<&'a str>, F, T>(
    f: F,
) -> impl Parser<&'a str, Output = Vec<d::PortOperator>, Error = E>
where
    T: Into<bool> + Clone,
    F: Parser<&'a str, Output = (T, Vec<d::Tuple<u16>>), Error = E>,
{
    map(f, |(operator, values)| {
        values
            .into_iter()
            .map(|i| d::PortOperator::new(operator.clone(), i))
            .collect()
    })
}

pub fn packet_length<'a, E: ParseError<&'a str>, F, T>(
    f: F,
) -> impl Parser<&'a str, Output = d::PacketLength, Error = E>
where
    T: Into<bool> + Into<bool>,
    F: Parser<&'a str, Output = (T, d::Tuple<u16>), Error = E>,
{
    map(f, |(operator, value)| d::PacketLength::new(operator, value))
}

pub fn ttl<'a, E: ParseError<&'a str>, F, T>(
    f: F,
) -> impl Parser<&'a str, Output = d::TTL, Error = E>
where
    T: Into<d::TTLOperatorType>,
    F: Parser<&'a str, Output = (T, u8), Error = E>,
{
    map(f, |(operator, value)| d::TTL::new(operator, value))
}

pub fn dscp<'a, E: ParseError<&'a str>, F>(
    f: F,
) -> impl Parser<&'a str, Output = d::DSCP, Error = E>
where
    F: Parser<&'a str, Output = (d::DSCPOperatorType, u8), Error = E>,
{
    map(f, |(operator, value)| d::DSCP::new(operator, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pair() {
        let (remain, res) = SingleOrPairU16::sep_colon("300:400").unwrap();
        assert_eq!(remain, "");
        if let d::Tuple::Pair(v1, v2) = res {
            assert_eq!(v1, 300);
            assert_eq!(v2, 400)
        }
    }

    #[test]
    fn test_separated_by_comma() {
        let mut ports = separated_by_comma(SingleOrPairU16::sep_colon);
        let (remain, res) = ports.parse("22,23").unwrap();
        assert_eq!(remain, "");
        let f = &res[0];
        if let d::Tuple::Single(v) = f {
            assert_eq!(*v, 22)
        }

        let f = &res[1];
        if let d::Tuple::Single(v) = f {
            assert_eq!(*v, 23)
        }
    }
}
