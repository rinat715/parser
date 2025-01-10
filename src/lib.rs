use nom::{
    bytes::complete::{tag, take_until, take_while, is_not}, 
    character::complete::{multispace1, multispace0}, 
    sequence::{delimited, tuple}, 
    Compare, 
    FindSubstring, 
    IResult, 
    InputLength, 
    InputTake, 
};




#[allow(dead_code)]
fn value_by_tag<T, Input>(tag_: T, end: T) -> impl Fn(Input) -> IResult<Input, Input> 
where
  Input: InputTake + FindSubstring<T> + Compare<T>,
  T: InputLength + Copy,
{
    move |input| {
        let (i, _) = tag(tag_)(input)?;
        take_until(end)(i)
    }

}


#[allow(dead_code)]
fn remove_spaces(input: &str) -> IResult<&str, &str>{
    delimited(
        multispace0,
        is_not(" \t\r\n"),
        multispace0
    )(input)
}



#[allow(dead_code)]
fn name(input: &str) -> IResult<&str, &str> {
    let dash = take_while(|c| c == '-');
    let left = (&dash, tag("["));
    let right = (tag("]"), &dash);

    let (_, (_, a))= delimited(tuple(left), tuple((multispace1,value_by_tag("Rule:", "]"))), tuple(right))(input)?;
    remove_spaces(a)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_test() {
        let arg = "-------------[ Rule: First_test_rule ]--------------";
        let result = name(arg);
        assert_eq!(result, Ok(("", "First_test_rule")));
        
    }
}
