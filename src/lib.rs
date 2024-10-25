use nom::{
    bytes::complete::{tag, take_until, take_while}, character::complete::multispace1, sequence::{delimited, tuple}, IResult, InputLength, InputTake, Compare,
    error::ParseError

};

#[allow(dead_code)]
fn get_name(input: &str) -> IResult<&str, &str> {
    let (i, _) = tag("Rule: ")(input)?;
    take_until(" ]")(i)
}


pub fn get_name2<T, Input, Error: ParseError<Input>>(
    start: T, stop: T
  ) -> impl FnOnce(Input) -> IResult
  where
    Input: InputTake + Compare<T>,
    T: InputLength + Clone,
  {
    move |i: Input| {
        let (a, _) = tag(start)(i)?;
        take_until(stop)(a)?;
    };
  }



fn identity<T>(a: T) -> T {
    return a;
}

fn right<T>(_a: T) -> impl Fn(T) -> T {
    return identity;
}



fn get_value(start: &str, stop: &str) -> impl Fn(InputLength) -> IResult<&str, &str>
{
    let (i, _) = tag(start)(input)?;
    take_until(stop)(i)
}



#[allow(dead_code)]
fn name(input: &str) -> IResult<&str, &str> {
    let left = (take_while(|c| c == '-'), tag("["), multispace1);
    let right = (multispace1, tag("]"), take_while(|c| c == '-'));
    

    let mut parser = delimited(tuple(left), get_name, tuple(right));

    parser(input)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_test() {
        // let arg = "Rule: First_test_rule";
        let arg = "-------------[ Rule: First_test_rule ]--------------";
        let result = name(arg);
        assert_eq!(result, Ok(("", "First_test_rule")));
        
    }

    #[test]
    fn get_name_test() {
        // let arg = "Rule: First_test_rule";
        let arg = "Rule: First_test_rule ]--------------";
        let result = get_name(arg);
        assert_eq!(result, Ok((" ]--------------", "First_test_rule")));
        
    }
}
