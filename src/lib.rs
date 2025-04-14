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
        let result = name(arg);
        assert_eq!(result, Ok((" -j REJECT --reject-with tcp-reset", "INPUT")));
    }

    #[test]
    fn jump_test() {
        let arg = "-j REJECT --reject-with tcp-reset";
        let result = jump(arg);
        assert_eq!(result, Ok((" --reject-with tcp-reset", "REJECT")));
    }

    #[test]
    fn reject_with_test() {
        let arg = "--reject-with tcp-reset -";
        let result = reject_with(arg);
        assert_eq!(result, Ok((" -", "tcp-reset")));
    }

    #[test]
    fn reject_with_test_2() {
        let arg = "--reject-with tcp-reset";
        let result = reject_with(arg);
        assert_eq!(result, Ok(("", "tcp-reset")));
    }
}


fn until_eof(s: &str) -> IResult<&str, &str> {
    alt((take_until(" -"), not_line_ending))(s)
  }



#[allow(dead_code)]
fn name(s: &str) -> IResult<&str, &str>{
    let (input, _) = preceded(tag("-A"), space1)(s)?;
    until_eof(input)
}


#[allow(dead_code)]
fn jump(s: &str) -> IResult<&str, &str>{
    let (input, _) = preceded(tag("-j"), space1)(s)?;
    until_eof(input)
}


#[allow(dead_code)]
fn reject_with(s: &str) -> IResult<&str, &str>{
    let (input, _) = preceded(tag("--reject-with"), space1)(s)?;
    until_eof(input)
}