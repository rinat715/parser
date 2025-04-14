use nom::{
    branch::alt, bytes::complete::{is_a, tag, take_until,}, character::complete::{char, space1}, combinator::{opt, rest}, error, multi::many_m_n, IResult
};
use nom::sequence::{pair,preceded};
use nom::character::complete::{alphanumeric1, not_line_ending};


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
}


#[derive(Debug,PartialEq)]
struct Token<'a> {
    negative:  bool,
    value:  &'a str,
    name: &'static str
}

// impl Default for Token<'_> {
//     fn default() -> Self {
//         Self {negative: false , value: Default::default(), name: Default::default()}
//     }
// }

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
        let (input, _) = preceded(tag(arg), space1)(input)?;
        let (input, value) = until_eof(input)?;
        let (name, _) = remove_dash(arg)?;
        
        Ok((input, Token{negative: false, value, name}))
    }
}


// #[allow(dead_code)]
// fn token(arg: &'static str) -> impl Fn(&str) ->  IResult<&str, &str>{
//     move |input: &str | {
//         let dash =  many_m_n(1, 2,char('-'));
//         let (other, (neg, *, res)) = (opt(tag(" ! ")),  space0, dash, tag(arg), char(' '), take_until_eof).parse(input)?;
        
//         Ok((other, res))
//     }
// }

