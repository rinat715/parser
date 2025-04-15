use std::collections::btree_map::IterMut;

use nom::{
    branch::alt, bytes::complete::{is_a, tag, take_until,}, character::complete::{char, space1}, combinator::{opt, rest}, error, multi::many_m_n, IResult
};
use nom::sequence::{pair,preceded};
use nom::character::complete::{alphanumeric1, not_line_ending};
use nom::branch::permutation;
use nom::multi::many1;
use nom::character::complete::space0;


#[derive(Debug,PartialEq,Default)]
struct ActionSetting {
    action: String,
    option: String
}


#[derive(Debug,PartialEq,Default)]
struct ACLRule {
    name: String,
    action: Vec<ActionSetting>,
    action_modifiers: Vec<ActionSetting>,
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
            action: vec![ActionSetting{action: "GOTO".to_string(), option: "MY_CHAIN".to_string()}],
            ..Default::default()
        })))
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


#[allow(dead_code)]
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

#[allow(dead_code)]
fn action(a: &Vec<Token>) -> ActionSetting{
    let mut res: ActionSetting = Default::default();

    for i in a  {
        match i.name {
            "g" => {
                res.action = String::from("GOTO");
                res.option = String::from(i.value)
            }
            "j" => {
                res.action = String::from("REJECT");
                res.option = String::from(i.value)
            }

            _ => res.action = String::from("PASS")
        }
    }

    return res

}


#[allow(dead_code)]
fn rule(s: &str) -> IResult<&str, ACLRule>{
    let mut rule: ACLRule = Default::default();

    let (input, name) =  token("-A")(s)?;

    rule.name = name.value.to_string();

    let (input, res) = parser(input)?;

    rule.action = vec![action(&res)];

    Ok((input, rule))

}