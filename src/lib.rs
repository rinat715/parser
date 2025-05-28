use nom::character::complete::alpha1;
use nom::character::complete::not_line_ending;
use nom::character::complete::space0;
use nom::combinator::map_parser;
use nom::multi::{many1, fold_many1};
use nom::sequence::separated_pair;
use nom::sequence::{preceded, tuple};
use nom::Parser;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::space1,
    combinator::{map, opt, value, verify, iterator},
    IResult,
};
use serde_derive::Serialize;
use std::collections::HashMap;

use std::str::FromStr;
mod domain;
use domain as d;

#[cfg(test)]
mod tests {
    use super::*;
    use tester::tester;

    // #[tester("token_a.toml")]
    // fn token_a(arg: &str) -> IResult<&str, (&str, ResultEnum>> {
    //     name(arg)
    // }

    #[tester("token_j.toml")]
    fn test_token_j(arg: &str) -> IResult<&str, Token> {
        token_with_value("-j")(arg)
    }

    #[tester("token_reject_with.toml")]
    fn token_reject_with(arg: &str) -> IResult<&str, Token> {
        token_with_value("--reject-with")(arg)
    }

    #[tester("token_log.toml")]
    fn token_log(arg: &str) -> IResult<&str, Token> {
        token("--log-ip-options")(arg)
    }

    // #[tester("parser.toml")]
    // fn test_parser(arg: &str) -> IResult<&str, HashMap<&str, ResultEnum>> {
    //     parser_new(arg)
    // }


    #[test]
    fn test_parser_new() {
        let (remaining, result) = parser_new(" -j REJECT").unwrap();
        assert_eq!(remaining, "");
        assert_eq!(result.get("jump"), Some(&ResultEnum::ActionType(d::ActionType::REJECT)));
    }

    #[test]
    fn action_test() {
        let arg = vec![Token {
            name: "j",
            negative: false,
            value: Some("ACCEPT"),
        }];
        let user = vec![];
        let res = ActionSettingBuilder::new(&user).build(&arg);
        assert_eq!(res, d::ActionSetting::new(d::ActionType::ACCEPT, ""))
    }

    #[test]
    fn action_goto_test() {
        let arg = vec![Token {
            name: "g",
            negative: false,
            value: Some("MY CHAIN"),
        }];
        let user = vec![];
        let res = ActionSettingBuilder::new(&user).build(&arg);
        assert_eq!(res, d::ActionSetting::new(d::ActionType::GOTO, "MY CHAIN"))
    }

    #[test]
    fn action_jump_test() {
        let arg = vec![Token {
            name: "j",
            negative: false,
            value: Some("MY CHAIN"),
        }];
        let user = vec!["MY CHAIN"];
        let res = ActionSettingBuilder::new(&user).build(&arg);
        assert_eq!(res, d::ActionSetting::new(d::ActionType::JUMP, "MY CHAIN"))
    }
}

#[derive(Debug, PartialEq, Serialize, Default)]
struct Token<'a> {
    name: &'a str,
    negative: bool,
    value: Option<&'a str>,
}

impl<'a> Token<'a> {
    fn new(name: &'a str, value: Option<&'a str>, negative: bool) -> Self {
        Self {
            name: name,
            negative: negative,
            value: value,
        }
    }
}

#[derive(Debug, PartialEq, Serialize)]
enum ResultEnum<'a> {
    ActionType(d::ActionType),
    Goto(d::ActionSetting<'a>),
    Name(&'a str),
}

fn action<'a>(input: &str) -> IResult<&str, (&str, ResultEnum)> {
    let parser = verify(alpha1, |s: &str| d::ActionType::from_str(s).is_ok());
    map(
        preceded(tuple((space1, tag("-j"), space1)), parser),
        |value| ("jump", ResultEnum::ActionType(d::ActionType::from_str(value).unwrap())),
    )
    .parse(input)
}

fn goto<'a>(input: &str) -> IResult<&str, (&str, ResultEnum)> {
    map(
        preceded(tuple((space1, tag("-g"), space1)), until_eof),
        |value| ("goto", ResultEnum::Goto(d::ActionSetting::new(d::ActionType::GOTO, value))),
    )
    .parse(input)
}

fn name<'a>(input: &str) -> IResult<&str, (&str, ResultEnum)> {
    map(preceded(tuple((tag("-A"), space1)), until_eof), |value| {
        ("name", ResultEnum::Name(value))
    })
    .parse(input)
}

fn parser_new(input: &str) -> IResult<&str, HashMap<&str, ResultEnum>> {
    let (remain, res) = many1(alt((action, goto))).parse(input)?;
    let m = res.into_iter().collect();
    Ok((remain, m))
}

fn until_eof(s: &str) -> IResult<&str, &str> {
    let is_next = alt((take_until(" !"), take_until(" -")));

    alt((is_next, not_line_ending))(s)
}

fn tag_(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| tag(arg).parse(input)
}

fn is_tag(arg: &'static str) -> impl Fn(&str) -> IResult<&str, Token> {
    move |input: &str| {
        let name_parser = map(alt((tag("--"), tag("-"))), |name| {
            Token::new(name, Option::None, false)
        });
        let mut parser = map_parser(tag_(arg), name_parser);
        parser.parse(input)
    }
}

fn tag_value(arg: &'static str) -> impl Fn(&str) -> IResult<&str, Token> {
    move |input: &str| {
        let mut parser = map(
            separated_pair(tag_(arg), space1, until_eof),
            |(name, value)| Token::new(name, Option::Some(value), false),
        );
        parser.parse(input)
    }
}

fn token_with_value(arg: &'static str) -> impl Fn(&str) -> IResult<&str, Token> {
    move |input: &str| preceded(space1, tag_value(arg)).parse(input)
}

fn token(arg: &'static str) -> impl Fn(&str) -> IResult<&str, Token> {
    move |input: &str| {
        let mut parser = preceded(space1, is_tag(arg));
        parser.parse(input)
    }
}

fn rule_name(arg: &'static str) -> impl Fn(&str) -> IResult<&str, Token> {
    move |input: &str| tag_value(arg).parse(input)
}

struct ActionSettingBuilder<'a> {
    user_chains: &'a Vec<&'a str>,
}
impl<'a> ActionSettingBuilder<'a> {
    fn new(user_chains: &'a Vec<&str>) -> Self {
        Self { user_chains }
    }

    fn action(&self, action: &'a str, option: &'a str) -> d::ActionSetting<'a> {
        d::ActionType::from_str(action)
            .map(|action_type| {
                match action_type {
                    d::ActionType::ACCEPT
                    | d::ActionType::DROP
                    | d::ActionType::QUEUE
                    | d::ActionType::RETURN
                    | d::ActionType::LOG
                    | d::ActionType::NFLOG
                    | d::ActionType::PASS => d::ActionSetting::new(action_type, ""),

                    d::ActionType::REJECT | d::ActionType::GOTO => {
                        if option == "" {
                            panic!() // TODO
                        }
                        return d::ActionSetting::new(action_type, option);
                    }

                    d::ActionType::JUMP => panic!(), // TODO,
                }
            })
            .ok()
            .or_else(|| {
                self.user_chains
                    .contains(&action)
                    .then_some(d::ActionSetting::new(d::ActionType::JUMP, action))
            })
            .unwrap_or(d::ActionSetting::new(domain::ActionType::PASS, ""))
    }

    fn get_value(&self, name: &'static str, a: &Vec<Token<'a>>) -> Option<&'a str> {
        a.iter()
            .find(by_name(name))
            .map(|option| option.value)
            .and_then(|value| value)
    }

    fn build(&self, a: &Vec<Token<'a>>) -> d::ActionSetting<'a> {
        self.get_value("g", a)
            .map(|value| self.action("GOTO", value))
            .unwrap_or_else(|| {
                self.action(
                    self.get_value("j", a).unwrap_or_default(),
                    self.get_value("reject-with", a).unwrap_or_default(),
                )
            })
    }
}

fn by_name(name: &'static str) -> impl FnMut(&&Token) -> bool {
    move |item| item.name == name
}

fn parser(input: &str) -> IResult<&str, Vec<Token>> {
    many1(alt((
        token_with_value("-j"),
        token_with_value("--reject-with"),
        token_with_value("-g"),
        token_with_value("--log-level"),
        token("--log-prefix"),
        token("--log-tcp-sequence"),
        token("--log-tcp-options"),
        token("--log-ip-options"),
        token("--log-uid"),
        token_with_value("-p"),
    )))(input)
}

pub fn rule<'a>(s: &'a str, user_chains: &'a Vec<&'a str>) -> IResult<&'a str, d::ACLRule<'a>> {
    let (input, name) = rule_name("-A")(s)?;

    let (input, tokens) = parser(input)?;

    let action = ActionSettingBuilder::new(user_chains).build(&tokens);

    let normalized_action = action.normalized_action().ok();

    Ok((
        input,
        d::ACLRule::new(action, normalized_action, name.value.unwrap()),
    ))
}
