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
mod domain;
use domain as d;

#[cfg(test)]
mod tests {
    use super::*;
    use tester::tester;

    #[tester("token_a.toml")]
    fn token_a(arg: &str) -> IResult<&str, Token> {
        token("-A")(arg)
    }

    #[tester("token_j.toml")]
    fn test_token_j(arg: &str) -> IResult<&str, Token> {
        token("-j")(arg)
    }

    #[tester("token_g.toml")]
    fn test_token_g(arg: &str) -> IResult<&str, Token> {
        token("-g")(arg)
    }

    #[tester("token_reject_with.toml")]
    fn token_reject_with(arg: &str) -> IResult<&str, Token> {
        token("--reject-with")(arg)
    }

    #[tester("parser.toml")]
    fn test_parser(arg: &str) -> IResult<&str, Vec<Token>> {
        parser(arg)
    }

    // #[tester("acl.toml")]
    // fn test_rule(arg: &str) -> IResult<&str, ACLRule> {
    //     rule(arg)
    // }

    #[test]
    fn action_test() {
        let arg = vec![Token {
            name: "j",
            negative: false,
            value: "ACCEPT",
        }];
        let res = action(&arg);
        assert_eq!(
            res,
            d::ActionSetting::new(d::ActionType::ACCEPT, "")
        )
    }
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


fn build<'a>(action: &'a str, option: &'a str) -> d::ActionSetting<'a> {
    if let Ok(action_type) = d::ActionType::from_str(action) {
        match action_type {
            d::ActionType::ACCEPT
            | d::ActionType::DROP
            | d::ActionType::QUEUE
            | d::ActionType::RETURN
            | d::ActionType::LOG => return d::ActionSetting::new(action_type, ""),
            d::ActionType::REJECT => return d::ActionSetting::new(action_type, option),

            _ => {
                // if self.user_chains.contains(&action) {
                //     return d::ActionSetting::new(d::ActionType::JUMP, action);
                // }
                panic!()
            }
        }
    }

    d::ActionSetting::new(domain::ActionType::PASS, "")
}


fn parser(input: &str) -> IResult<&str, Vec<Token>> {
    many1(alt((token("-j"), token("--reject-with"), token("-g"))))(input)
}

fn action<'a>(a: &Vec<Token<'a>>) -> d::ActionSetting<'a> {
    if let Some(option) = a.iter().find(|&x| x.name == "g") {
        return build("GOTO", option.value);
    }

    if let Some(action) = a.iter().find(|&x| x.name == "j") {
        if let Some(option) = a.iter().find(|&x| x.name == "reject-with") {
            return build(action.value, option.value);
        } else {
            return build(action.value, "");
        }
    }
    build("", "")
}

// pub fn rule<'a>(s: &'a str) -> IResult<&str, d::ACLRule<'a>> {
//     let mut rule: d::ACLRule = Default::default();

//     let (input, name) = token("-A")(s)?;

//     rule.name = name.value.to_string();

//     let (input, res) = parser(input)?;

//     rule.action = vec![action(&res)];

//     action(&res);

//     Ok((input, rule))
// }
