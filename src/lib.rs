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

    test_parser!(test_token_a, "token_a.toml", token("-A"));

    test_parser_struct!(test_token_g, "token_g.toml", get_goto);
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


enum ResultParser {
    Name,
    ActionSetting
}



// pub fn rule<'a>(input: &'a str) -> IResult<&str, ACLRule<'a>> {
//     let mut rule: ACLRule = Default::default();


//     //let mut parser: IResult<&str, Vec<ResultParser>> =many1(alt((get_name, get_goto)))(input);


//     Ok((input, rule))
// }
