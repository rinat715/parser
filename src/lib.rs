use domain::ActionSetting;
use nom::character::complete::alpha1;
use nom::character::complete::not_line_ending;
use nom::character::complete::space0;
use nom::combinator::map_parser;
use nom::multi::{fold_many1, many1};
use nom::sequence::separated_pair;
use nom::sequence::{preceded, tuple};
use nom::Parser;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::space1,
    combinator::{iterator, map, map_res, value, verify},
    IResult,
};
use serde::de::value;
use serde_derive::Serialize;
use std::collections::HashMap;

use std::str::FromStr;
mod domain;
use domain as d;

#[derive(Debug, PartialEq, Eq)]
pub struct ParseEnum2Error; // TODO нормальное название

#[cfg(test)]
mod tests {
    use super::*;
    use tester::tester;

    #[test]
    fn test_parser_new() {
        let (remaining, result) = parser(" -j REJECT").unwrap();
        assert_eq!(remaining, "");
        assert_eq!(result.get("jump"), Some(&"REJECT"));
    }
}

#[derive(Debug, PartialEq, Serialize)]
enum Result<'a> {
    ActionType(d::ActionType),
    ActionSetting(d::ActionSetting<'a>),
}

fn action<'a>(input: &str) -> IResult<&str, &str> {
    let parser = verify(alpha1, |s: &str| d::ActionType::from_str(s).is_ok());
    preceded(tuple((space1, tag("-j"), space1)), parser).parse(input)
}

fn jump<'a>(input: &str) -> IResult<&str, &str> {
    let parser = verify(alpha1, |s: &str| d::ActionType::from_str(s).is_ok());
    preceded(tuple((space1, tag("-j"), space1)), parser).parse(input)
}

fn name<'a>(input: &str) -> IResult<&str, &str> {
    preceded(tuple((tag("-A"), space1)), until_eof).parse(input)
}

fn tag_value(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded(tuple((space1, tag(arg), space1)), until_eof).parse(input)
}

fn is_tag(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| value("", preceded(space1, tag(arg))).parse(input)
}

fn parser(input: &str) -> IResult<&str, HashMap<&str, &str>> {
    let (remain, res) = many1(alt((
        map(action, |value| ("jump", value)),
        map(tag_value("-g"), |value| ("goto", value)),
        map(tag_value("--log-level"), |value| ("log_level", value)),
        map(tag_value("--log-prefix"), |value| ("log-prefix", value)),
        map(is_tag("--log-tcp-sequence"), |value| {
            ("log-tcp-sequence", value)
        }),
        map(is_tag("--log-tcp-options"), |value| {
            ("log-tcp-options", value)
        }),
        map(is_tag("--log-ip-option"), |value| ("log-ip-option", value)),
    )))
    .parse(input)?;
    Ok((remain, res.into_iter().collect()))
}

fn until_eof(s: &str) -> IResult<&str, &str> {
    let is_next = alt((take_until(" !"), take_until(" -")));

    alt((is_next, not_line_ending))(s)
}

pub fn rule<'a>(s: &'a str) -> IResult<&'a str, d::ACLRule<'a>> {
    let (input, name) = name(s)?;

    let (input, tokens) = parser(input)?;

    let action = tokens
        .get("goto")
        .map(|value| d::ActionSetting::new(d::ActionType::GOTO, value))
        .or(tokens
            .get("jump")
            .map(|value| d::ActionSetting::new(d::ActionType::from_str(value).unwrap(), "")))
        .unwrap_or(ActionSetting::new(domain::ActionType::PASS, ""));

    let normalized_action = action.normalized_action().ok();

    Ok((input, d::ACLRule::new(action, normalized_action, name)))
}
