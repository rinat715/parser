use nom::{
    branch::alt, bytes::complete::{is_a, is_not, tag, take_until}, character::complete::{char, tab}, error::ParseError, multi::many0_count, sequence::pair, IResult
};
use nom::sequence::Tuple;
use nom::character::complete::space0;
use nom::error::Error;

#[allow(dead_code)]
fn delimeter(input: &str) -> IResult<&str, char> {
    let (i, _) = is_a("-")(input)?;
    let (a, b) = alt((char('['), char(']')))(i)?;
    Ok((a, b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delimeter_test() {
        let arg = "--[";
        let result = delimeter(arg);
        assert_eq!(result, Ok(("", '[')));
        
        let arg = "--]";
        let result = delimeter(arg);
        assert_eq!(result, Ok(("", ']')));
    }

    
    #[test]
    fn chan_test() {
        let arg = "-A INPUT";
        let result = chain(arg);
        assert_eq!(result, Ok(("", "INPUT")));

        let arg = "-A INPUT -j LOG --log-prefix \"hello guys\"";
        let result = chain(arg);
        assert_eq!(result, Ok((" -j LOG --log-prefix \"hello guys\"", "INPUT")));

        let arg = "-A INPUT dfd -j LOG --log-prefix \"hello guys\"";
        let result = chain(arg);
        assert_eq!(result, Ok((" -j LOG --log-prefix \"hello guys\"", "INPUT dfd")));

        
        let arg = "-A INPUT ! -s 10.0.0.56/30";
        let result = chain(arg);
        assert_eq!(result, Ok((" ! -s 10.0.0.56/30", "INPUT")));
    }
}



  fn take_until_dash(s: &str) -> IResult<&str, &str> {
    match take_until::<&str, &str, Error<&str>>(" -")(s) {
        Ok(result) => Ok(result),
        Err(_) => Ok(("", s)),
    }
  }


fn take_until_eof(s: &str) -> IResult<&str, &str>{
    match take_until::<&str, &str, Error<&str>>(" ! ")(s) {
        Ok(result) => Ok(result),
        Err(_) => take_until_dash(s),
    }
    
}


fn dash(s: &str)  -> IResult<&str, char> {
    char('-')(s)
}


// -A INPUT

// #[allow(dead_code)]
// fn chain(input: &str) -> IResult<&str, &str> {
//     let tag = char('A');
//     let (other, (_,  _, _, _, res)) = (space0, many0_count(dash), tag, char(' '), take_until_eof).parse(input)?;

//     Ok((other, res))
// }

#[allow(dead_code)]
fn chain<I, Error: ParseError<I>>(c: char) -> impl Fn(I) -> IResult<I, char, Error>{
    let tag = char('A');
    let (other, (_,  _, _, _, res)) = (space0, many0_count(dash), tag, char(' '), take_until_eof).parse(input)?;

    Ok((other, res))
}

#[allow(dead_code)]
fn jump(input: &str) -> IResult<&str, &str> {
    let tag = char('j');
    let (other, (_,  _, _, res)) = (dash, tag, char(' '), take_until_eof).parse(input)?;

    Ok((other, res))
}