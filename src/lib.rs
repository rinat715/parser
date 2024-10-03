use nom::{
    branch::alt,
    bytes::complete::is_a,
    character::complete::char,
    IResult,
};

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
}
