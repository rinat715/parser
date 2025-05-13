use nom::character::complete::not_line_ending;
use nom::character::complete::space0;
use nom::multi::many1;
use nom::sequence::preceded;
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
    fn token_a(arg: &str) ->  IResult<&str, Token> {
        token("-A")(arg)
    }

    #[tester("token_j.toml")]
    fn test_token_j(arg: &str) ->  IResult<&str, Token> {
        token("-j")(arg)
    }

    #[tester("token_g.toml")]
    fn test_token_g(arg: &str) ->  IResult<&str, Token> {
        token("-g")(arg)
    }

    #[tester("token_reject_with.toml")]
    fn token_reject_with(arg: &str) ->  IResult<&str, Token> {
        token("--reject-with")(arg)
    }

    #[tester("parser.toml")]
    fn test_parser(arg: &str) -> IResult<&str, Vec<Token>> {
        parser(arg)
    }



    // test_parser_struct!(test_acl, "acl.toml", rule);

    // #[test]
    // fn action_test() {
    //     let arg = vec![Token {
    //         name: "j",
    //         negative: false,
    //         value: "ACCEPT",
    //     }];
    //     let res = action(&arg);
    //     assert_eq!(
    //         res,
    //         ActionSetting {
    //             action: ActionType::ACCEPT,
    //             option: ""
    //         }
    //     )
    // }
}

#[derive(Debug, PartialEq, Serialize)]
struct Token<'a> {
    name: &'a str,
    negative: bool,
    value: &'a str,
}

fn remove_dash(s: &str) -> IResult<&str, &str> {
    alt((tag("--"), tag("-")))(s)
}

fn until_eof(s: &str) -> IResult<&str, &str> {
    let is_next = alt((take_until(" !"), take_until(" -")));

    alt((is_next, not_line_ending))(s)
}

fn token(arg: &'static str) -> impl Fn(&str) -> IResult<&str, Token> {
    move |input: &str| {
        let (input, _) = space0(input)?;
        let (input, _) = preceded(tag(arg), space1)(input)?;
        let (input, value) = until_eof(input)?;
        let (name, _) = remove_dash(arg)?;

        Ok((
            input,
            Token {
                negative: false,
                value,
                name,
            },
        ))
    }
}

fn parser(input: &str) -> IResult<&str, Vec<Token>> {
    many1(alt((token("-j"), token("--reject-with"), token("-g"))))(input)
}

fn action<'a>(a: &Vec<Token<'a>>) -> ActionSetting<'a> {
    let goto = a.iter().find(|&x| x.name == "g").map(|x| ActionSetting {
        action: ActionType::GOTO,
        option: x.value,
    });
    let jump = a.iter().find(|&x| x.name == "j").map(|x| {
        let action_type = ActionType::from_str(x.value).unwrap_or_default();
        ActionSetting {
            action: action_type,
            option: Default::default(),
        }
    });

    goto.or(jump).unwrap_or_default()
}

pub fn rule<'a>(s: &'a str) -> IResult<&str, ACLRule<'a>> {
    let mut rule: ACLRule = Default::default();

    let (input, name) = token("-A")(s)?;

    rule.name = name.value.to_string();

    let (input, res) = parser(input)?;

    rule.action = vec![action(&res)];

    action(&res);

    Ok((input, rule))
}
