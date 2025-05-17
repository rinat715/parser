use nom::character::complete::not_line_ending;
use nom::character::complete::space0;
use nom::combinator::map;
use nom::multi::many1;
use nom::sequence::preceded;
use nom::Parser;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::space1,
    IResult,
};
use serde_derive::Serialize;
use std::str::FromStr;

#[derive(Debug, PartialEq, Eq)]
struct ParseEnumError;

#[derive(Debug, PartialEq, Default, Serialize)]
enum ActionType {
    ACCEPT,
    GOTO,
    REJECT,
    QUEUE,
    DROP,
    RETURN,
    LOG,
    NFLOG,
    #[default]
    PASS,
}

impl FromStr for ActionType {
    type Err = ParseEnumError;

    fn from_str(o: &str) -> Result<Self, Self::Err> {
        match o {
            "ACCEPT" => Ok(Self::ACCEPT),
            "REJECT" => Ok(Self::REJECT),
            "DROP" => Ok(Self::DROP),
            "QUEUE" => Ok(Self::QUEUE),
            "RETURN" => Ok(Self::RETURN),
            "LOG" => Ok(Self::LOG),
            "NFLOG" => Ok(Self::NFLOG),

            _ => Err(ParseEnumError),
        }
    }
}

#[derive(Debug, PartialEq, Default, Serialize)]
struct ActionSetting<'a> {
    action: ActionType,
    option: &'a str,
}

#[derive(Debug, PartialEq, Default, Serialize)]
pub struct ACLRule<'a> {
    action_modifiers: Vec<ActionSetting<'a>>,
    name: String,
    action: Vec<ActionSetting<'a>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tester::tester;

    #[tester("token_a.toml")]
    fn token_a(arg: &str) -> IResult<&str, &str> {
        token("-A")(arg)
    }

    #[tester("token_g.toml")]
    fn token_goto(arg: &str) -> IResult<&str, ActionSetting> {
        get_goto(arg)
    }
}

fn remove_dash(s: &str) -> IResult<&str, &str> {
    alt((tag("--"), tag("-")))(s)
}

fn until_eof(s: &str) -> IResult<&str, &str> {
    let is_next = alt((take_until(" !"), take_until(" -")));

    alt((is_next, not_line_ending))(s)
}

fn token(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| {
        let (input, _) = space0(input)?;
        let (input, _) = preceded(tag(arg), space1)(input)?;
        until_eof(input)
    }
}

fn get_action_modifier(arg: &'static str) -> impl Fn(&str) -> IResult<&str, ActionSetting> {
    move |input: &str| {
        let mut parser = map(token(arg), |s: &str| ActionSetting {
            action: ActionType::GOTO,
            option: s,
        });
        parser.parse(input)
    }
}


struct Name<'a>(&'a str);

fn get_name(input: &str) -> IResult<&str, Name> {
    let mut parser = map(token("-A"), |s: &str| Name(s));
    parser.parse(input)
}

fn get_goto(input: &str) -> IResult<&str, ActionSetting> {
    let mut parser = map(token("-g"), |s: &str| ActionSetting {
        action: ActionType::GOTO,
        option: s,
    });
    parser.parse(input)
}

fn get_action_type(input: &str) -> IResult<&str, ActionType> {
    let mut parser = map(token("-j"), |s: &str| ActionType::from_str(s).unwrap_or_default());
    parser.parse(input)
}

fn get_action_value(input: &str) -> IResult<&str, ActionType> {
    let mut parser = map(token("-j"), |s: &str| ActionType::from_str(s).unwrap_or_default());
    parser.parse(input)
}

enum ResultParser {
    Name,
    ActionSetting,
}

// pub fn rule<'a>(input: &'a str) -> IResult<&str, ACLRule<'a>> {
//     let mut rule: ACLRule = Default::default();

//     //let mut parser: IResult<&str, Vec<ResultParser>> =many1(alt((get_name, get_goto)))(input);

//     Ok((input, rule))
// }
