use nom::{
    branch::alt, bytes::complete::{tag, take_until}, character::complete::space1, IResult
};
use nom::sequence::preceded;
use nom::character::complete::not_line_ending;
use nom::multi::many1;
use nom::character::complete::space0;
use std::str::FromStr;


#[derive(Debug, PartialEq, Eq)]
struct ParseEnumError;



#[derive(Debug,PartialEq,Default)]
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
    PASS
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


#[derive(Debug,PartialEq,Default)]
struct ActionSetting <'a>{
    action: ActionType,
    option: &'a str
}


#[derive(Debug,PartialEq,Default)]
pub struct ACLRule <'a> {
    name: String,
    action: Vec<ActionSetting<'a>>,
    action_modifiers: Vec<ActionSetting<'a>>,
}



#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn name_test() {
        let arg = "-A INPUT -j REJECT --reject-with tcp-reset";
        let result = token("-A")(arg);
        assert_eq!(result, Ok((" -j REJECT --reject-with tcp-reset", Token{value: "INPUT", negative: false, name: "A"})));
    }

    #[test]
    fn name_test_2() {
        let arg = "-A INPUT dfdf -j REJECT --reject-with tcp-reset";
        let result = token("-A")(arg);
        assert_eq!(result, Ok((" -j REJECT --reject-with tcp-reset", Token{value: "INPUT dfdf", negative: false, name: "A"})));
    }

    #[test]
    fn jump_test() {
        let arg = "-j REJECT --reject-with tcp-reset";
        let result = token("-j")(arg);
        assert_eq!(result, Ok((" --reject-with tcp-reset", Token{value: "REJECT", negative: false, name: "j"})));
    }

    #[test]
    fn goto_test() {
        let arg = "-g MY CHAIN";
        let result = token("-g")(arg);
        assert_eq!(result, Ok(("", Token{value: "MY CHAIN", negative: false, name: "g"})));
    }

    #[test]
    fn reject_with_test() {
        let arg = "--reject-with tcp-reset -";
        let result = token("--reject-with")(arg);
        assert_eq!(result, Ok((" -", Token{value: "tcp-reset", negative: false, name: "reject-with"})));
    }

    #[test]
    fn reject_with_test_2() {
        let arg = "--reject-with tcp-reset";
        let result = token("--reject-with")(arg);
        assert_eq!(result, Ok(("", Token{value: "tcp-reset", negative: false, name: "reject-with"})));
    }

    #[test]
    fn reject_with_test_3() {
        let arg = "--reject-with tcp-reset\n";
        let result = token("--reject-with")(arg);
        assert_eq!(result, Ok(("\n", Token{value: "tcp-reset", negative: false, name: "reject-with"})));
    }

    #[test]
    fn reject_with_test_4() {
        let arg = "--reject-with tcp-reset !";
        let result = token("--reject-with")(arg);
        assert_eq!(result, Ok((" !", Token{value: "tcp-reset", negative: false, name: "reject-with"})));
    }

    #[test]
    fn parser_test() {
        let arg = "-j REJECT --reject-with tcp-reset";
        let res = parser(arg);
        assert_eq!(res, Ok(("", vec![Token{value: "REJECT", negative: false, name: "j"}, Token{value: "tcp-reset", negative: false, name: "reject-with"}])))
    }

    #[test]
    fn acl_1() {
        let arg = "-A INPUT -g MY_CHAIN --ctstate RELATED,ESTABLISHED";
        let res = rule(arg);
        assert_eq!(res, Ok((" --ctstate RELATED,ESTABLISHED", ACLRule{
            name: "INPUT".to_string(),
            action: vec![ActionSetting{action: ActionType::GOTO, option: "MY_CHAIN"}],
            ..Default::default()
        })))
    }

    #[test]
    fn action_test() {
        let arg =  vec![Token{name: "j", negative: false, value: "ACCEPT"}];
        let res = action(&arg);
        assert_eq!(res, ActionSetting{action: ActionType::ACCEPT, option: ""})
    }
}


#[derive(Debug,PartialEq)]
struct Token<'a> {
    negative:  bool,
    value:  &'a str,
    name: &'static str
}

fn remove_dash(s: &str) ->  IResult<&str, &str>{
    alt((tag("--"), tag("-")))(s)
    
}

fn until_eof(s: &str) -> IResult<&str, &str> {
    let is_next = alt((take_until(" !"), take_until(" -")));

    alt((is_next, not_line_ending))(s)
  }


fn token(arg: &'static str) -> impl Fn(&str) ->  IResult<&str, Token>{
    move |input: &str | {
        let (input, _) = space0(input)?;
        let (input, _) = preceded(tag(arg), space1)(input)?;
        let (input, value) = until_eof(input)?;
        let (name, _) = remove_dash(arg)?;
        
        Ok((input, Token{negative: false, value, name}))
    }
}

fn parser(input: &str) -> IResult<&str, Vec<Token>> {
    many1(alt((
        token("-j"), 
        token("--reject-with"),
        token("-g")
    )))(input)
  }


fn action<'a>(a: & Vec<Token<'a>>) -> ActionSetting<'a>{
    let goto = a.iter().find(| &x| x.name == "g").map(| x | ActionSetting { action:  ActionType::GOTO, option: x.value});
    let jump = a.iter().find(| &x| x.name == "j").map(
        | x | {
            let action_type = ActionType::from_str(x.value).unwrap_or(ActionType::PASS);
            ActionSetting { action: action_type, option: Default::default() }
        });

    goto.or(jump).unwrap_or_default()
}


pub fn rule<'a>(s: &'a str) -> IResult<&str, ACLRule<'a>>{
    let mut rule: ACLRule = Default::default();

    let (input, name) =  token("-A")(s)?;

    rule.name = name.value.to_string();

    let (input, res) = parser(input)?;

    rule.action = vec![action(&res)];

    action(&res);

    Ok((input, rule))

}
