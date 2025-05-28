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
        assert_eq!(
            result.get("jump"),
            Some(&Result::ActionType(d::ActionType::REJECT))
        );
    }
}

#[derive(Debug, PartialEq, Serialize)]
enum Result<'a> {
    ActionType(d::ActionType),
    ActionSetting(d::ActionSetting<'a>),
}

impl<'a> TryFrom<Result<'a>> for d::ActionType {
    type Error = ParseEnum2Error;
    
    fn try_from(other: Result) -> std::result::Result<Self, ParseEnum2Error> {
        match other {
            Result::ActionType(value) => Ok(value),
            _ => Err(ParseEnum2Error),
        }
    }
}

impl<'a> TryFrom<Result<'a>> for d::ActionSetting<'a> {
    type Error = ParseEnum2Error;
    
    fn try_from(other: &Result<'a>) -> std::result::Result<Self, ParseEnum2Error> {
        match other {
            Result::ActionSetting(value) => Ok(value),
            _ => Err(ParseEnum2Error),
        }
    }
}

fn action<'a>(input: &str) -> IResult<&str, Result> {
    let parser = verify(alpha1, |s: &str| d::ActionType::from_str(s).is_ok());
    map(
        preceded(tuple((space1, tag("-j"), space1)), parser),
        |value| Result::ActionType(d::ActionType::from_str(value).unwrap()),
    )
    .parse(input)
}

fn jump<'a>(input: &str) -> IResult<&str, Result> {
    let parser = verify(alpha1, |s: &str| d::ActionType::from_str(s).is_ok());
    map(
        preceded(tuple((space1, tag("-j"), space1)), parser),
        |value| Result::ActionType(d::ActionType::from_str(value).unwrap()),
    )
    .parse(input)
}

fn name<'a>(input: &str) -> IResult<&str, &str> {
    preceded(tuple((tag("-A"), space1)), until_eof).parse(input)
}

fn tag_value(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded(tuple((space1, tag(arg), space1)), until_eof).parse(input)
}

fn is_tag(arg: &'static str) -> impl Fn(&str) -> IResult<&str, ()> {
    move |input: &str| value((), preceded(space1, tag(arg))).parse(input)
}

fn parser(input: &str) -> IResult<&str, HashMap<&str, Result>> {
    let (remain, res) = many1(alt((
        map(action, |value| ("jump", value)),
        map(tag_value("-g"), |value| {
            (
                "goto",
                Result::ActionSetting(d::ActionSetting::new(d::ActionType::GOTO, value)),
            )
        }),
        map(tag_value("--log-level"), |value| {
            (
                "log_level",
                Result::ActionSetting(d::ActionSetting::new(d::ActionType::LogLevel, value)),
            )
        }),
        map(tag_value("--log-prefix"), |value| {
            (
                "log-prefix",
                Result::ActionSetting(d::ActionSetting::new(d::ActionType::LogPrefix, value)),
            )
        }),
        map(is_tag("--log-tcp-sequence"), |()| {
            (
                "log-tcp-sequence",
                Result::ActionSetting(d::ActionSetting::new(d::ActionType::LogTCPSequence, "")),
            )
        }),
        map(is_tag("--log-tcp-options"), |()| {
            (
                "log-tcp-options",
                Result::ActionSetting(d::ActionSetting::new(d::ActionType::LogTCPOptions, "")),
            )
        }),
        map(is_tag("--log-ip-option"), |()| {
            (
                "log-ip-option",
                Result::ActionSetting(d::ActionSetting::new(d::ActionType::LogIPOptions, "")),
            )
        }),
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

    let action: domain::ActionSetting<'a> =    tokens.get("goto").unwrap().try_into().unwrap();



    let normalized_action = action.normalized_action().ok();

    Ok((
        input,
        d::ACLRule::new(action, normalized_action, name.value.unwrap()),
    ))
}