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

    use serde_derive::Deserialize;
    use std::env;
    use std::env::VarError;
    use std::fs::File;
    use std::io::prelude::*;
    use std::path::PathBuf;
    use toml::Table;
    use toml::Value;

    #[derive(Deserialize)]
    struct TestSuit {
        input: String,
        remaining: String,
        expected: Value,
    }

    fn fixture_dir() -> Result<PathBuf, VarError> {
        let path = PathBuf::new();
        let manifest = env::var("CARGO_MANIFEST_DIR")?;

        Ok(path.join(manifest).join("fixtures"))
    }

    fn read_file_to_string(path: &str, buf: &mut String) {
        let mut f = File::open(path).unwrap();
        f.read_to_string(buf).unwrap();
    }

    macro_rules! test_parsers {
        ($func_name:ident, $file:literal, $function:expr) => {
            #[test]
            fn $func_name() {
                let test_file = fixture_dir().unwrap().join($file);

                let mut buffer = String::new();
                read_file_to_string(test_file.to_str().unwrap(), &mut buffer);

                for (test_name, value) in buffer.parse::<Table>().unwrap() {
                    println!("Run {}", test_name);

                    let test: TestSuit = value.try_into().unwrap();
                    let (remaining, result) = $function(&test.input).unwrap();

                    assert_eq!(remaining, test.remaining);
                    assert_eq!(
                        toml::to_string(&test.expected).unwrap(),
                        toml::to_string(&result).unwrap()
                    );
                }
            }
        };
    }

    macro_rules! test_parser_vec {
        ($func_name:ident, $file:literal, $function:expr) => {
            #[test]
            fn $func_name() {
                let test_file = fixture_dir().unwrap().join($file);

                let mut buffer = String::new();
                read_file_to_string(test_file.to_str().unwrap(), &mut buffer);

                for (test_name, value) in buffer.parse::<Table>().unwrap() {
                    println!("Run {}", test_name);

                    let test: TestSuit = value.try_into().unwrap();
                    let (remaining, results) = $function(&test.input).unwrap();
                    assert_eq!(remaining, test.remaining);

                    let mut index = 0;
                    for inner in test.expected.as_array().unwrap() {
                        println!("Run {}", index);
                        assert_eq!(
                            toml::to_string(&inner).unwrap(),
                            toml::to_string(&results[index]).unwrap()
                        );
                        index += 1
                    }
                }
            }
        };
    }

    test_parsers!(test_token_a, "token_a.toml", token("-A"));
    test_parsers!(test_token_j, "token_j.toml", token("-j"));
    test_parsers!(test_token_g, "token_g.toml", token("-g"));
    test_parsers!(
        test_token_reject_with,
        "token_reject_with.toml",
        token("--reject-with")
    );

    test_parser_vec!(test_parser, "parser.toml", parser);

    test_parsers!(test_acl, "acl.toml", rule);

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
            ActionSetting {
                action: ActionType::ACCEPT,
                option: ""
            }
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
