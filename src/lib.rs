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

#[derive(Debug, PartialEq, Default)]
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

#[derive(Debug, PartialEq, Default)]
struct ActionSetting<'a> {
    action: ActionType,
    option: &'a str,
}

#[derive(Debug, PartialEq, Default)]
pub struct ACLRule<'a> {
    name: String,
    action: Vec<ActionSetting<'a>>,
    action_modifiers: Vec<ActionSetting<'a>>,
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
    use toml::Value;
    use toml::Table;

    #[derive(Deserialize)]
    struct TestSuit {
        input: String,
        remaining: String,
        expected: Value,
        function: String,
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
        ($func_name:ident, $cases:expr) => {
            #[test]
            fn $func_name() {
                for (input, expected, remaining, func) in $cases {
                    let parsed = func(input);
                    assert_eq!(parsed, Ok((remaining, expected)));
                }
            }
        };
    }

    #[test]
    fn test_toml() {

        let fixture_dir = fixture_dir().unwrap();
        let test_file = fixture_dir.join("test.toml");

        let mut buffer = String::new();

        read_file_to_string(test_file.to_str().unwrap(), &mut buffer);

        let tables = buffer.parse::<Table>().unwrap();

        for (test_name, value) in tables {
            println!("Run {}", test_name);
            let test: TestSuit = value.try_into().unwrap();

            let (remaining, token) = token("-A")(&test.input).unwrap();
            assert_eq!(remaining, test.remaining);
            assert_eq!(
                toml::to_string(&test.expected).unwrap(),
                toml::to_string(&token).unwrap()
            );
        }

    }

    test_parsers!(
        test_token,
        [
            (
                "-A INPUT -j REJECT --reject-with tcp-reset",
                Token {
                    value: "INPUT",
                    negative: false,
                    name: "A"
                },
                " -j REJECT --reject-with tcp-reset",
                token("-A")
            ),
            (
                "-A INPUT dfdf -j REJECT --reject-with tcp-reset",
                Token {
                    value: "INPUT dfdf",
                    negative: false,
                    name: "A"
                },
                " -j REJECT --reject-with tcp-reset",
                token("-A")
            ),
            (
                "-j REJECT --reject-with tcp-reset",
                Token {
                    value: "REJECT",
                    negative: false,
                    name: "j"
                },
                " --reject-with tcp-reset",
                token("-j")
            ),
            (
                "-g MY CHAIN",
                Token {
                    value: "MY CHAIN",
                    negative: false,
                    name: "g"
                },
                "",
                token("-g")
            ),
            (
                "--reject-with tcp-reset -",
                Token {
                    value: "tcp-reset",
                    negative: false,
                    name: "reject-with"
                },
                " -",
                token("--reject-with")
            ),
            (
                "--reject-with tcp-reset",
                Token {
                    value: "tcp-reset",
                    negative: false,
                    name: "reject-with"
                },
                "",
                token("--reject-with")
            ),
            (
                "--reject-with tcp-reset\n",
                Token {
                    value: "tcp-reset",
                    negative: false,
                    name: "reject-with"
                },
                "\n",
                token("--reject-with")
            ),
            (
                "--reject-with tcp-reset !",
                Token {
                    value: "tcp-reset",
                    negative: false,
                    name: "reject-with"
                },
                " !",
                token("--reject-with")
            ),
        ]
    );

    #[test]
    fn parser_test() {
        let arg = "-j REJECT --reject-with tcp-reset";
        let res = parser(arg);
        assert_eq!(
            res,
            Ok((
                "",
                vec![
                    Token {
                        value: "REJECT",
                        negative: false,
                        name: "j"
                    },
                    Token {
                        value: "tcp-reset",
                        negative: false,
                        name: "reject-with"
                    }
                ]
            ))
        )
    }

    #[test]
    fn acl_1() {
        let arg = "-A INPUT -g MY_CHAIN --ctstate RELATED,ESTABLISHED";
        let res = rule(arg);
        assert_eq!(
            res,
            Ok((
                " --ctstate RELATED,ESTABLISHED",
                ACLRule {
                    name: "INPUT".to_string(),
                    action: vec![ActionSetting {
                        action: ActionType::GOTO,
                        option: "MY_CHAIN"
                    }],
                    ..Default::default()
                }
            ))
        )
    }

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
