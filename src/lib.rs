use nom::{
    branch::alt, bytes::complete::{is_a, tag, take_until}, character::complete::char, combinator::{opt, rest}, error, multi::many_m_n, IResult
};
use nom::sequence::Tuple;
use nom::character::complete::space0;
use yaml_rust2::{Yaml, YamlLoader};
use yaml_rust2::yaml::Hash;
use yaml_rust2::scanner::ScanError;
use std::result::Result;
use std::fmt;




#[derive(Debug, Clone)]
struct InvalidYamlError;

impl fmt::Display for InvalidYamlError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid yaml")
    }
}

impl From<ScanError> for InvalidYamlError {
    fn from(_: ScanError) -> InvalidYamlError {
        InvalidYamlError
    }
}


#[derive(Debug, PartialEq)]
struct ResultScheme {
    value: String,
    other: String
}

impl ResultScheme {
    fn new(other: &str, result: &str) -> Self {
        Self {value: result.into() , other: other.into() }
    }

    fn to_value(&mut self, args: &Hash) {

        macro_rules! assign {
            ( $var:ident = $default:expr ) => {
                if let Some(val) = args.get(stringify!($var)) {
                    self.$var = val.parse().unwrap_or_else(|_| $default);
                }
            };
            ( $var:ident ) => { assign!($var = unreachable!("no default provided")) };
        }

        assign!(result);
        assign!(other);
    }
    
}


#[allow(dead_code)]
#[derive(Debug, PartialEq)]
struct TestCase {
    name: String,
    param: String,
    result: ResultScheme,
}

impl TestCase {
    fn new(name: &str, param: &str, result: (&str, &str)) -> Self {
        Self { name: name.into(), param: param.into(), result: ResultScheme::new(result.0, result.1) }
    }
    
}


struct TestFile {
    docs: Vec<Yaml>
}


fn to_str(arg: &Yaml) -> Result<&str, InvalidYamlError> {
    match arg.as_str() {
        Some(result) => return Ok(result),
        None => return Err(InvalidYamlError),
    };
    
}


// fn load_yaml_file(s: &str) -> Result<Yaml, ScanError> {
//     let docs = YamlLoader::load_from_str(s)?;
//     let doc = docs[0].clone();
//     Ok(doc)
// }


fn parse_test(y: &Yaml) -> Result<&Hash, InvalidYamlError>{
    y.as_hash().ok_or(InvalidYamlError)
}


#[allow(dead_code)]
fn load_yaml_file(s: &str) -> Result<Vec<TestCase>, InvalidYamlError> {
    let docs = YamlLoader::load_from_str(s)?;
    let doc = &docs[0];
    
    let mut vec = Vec::new();

    for (name, test) in doc.as_hash().ok_or(InvalidYamlError)?.iter() {
        let name = name.as_str().ok_or(InvalidYamlError)?;
        let test = test.as_hash().unwrap();
        let param = test.get(&Yaml::String("$param".to_string())).unwrap().as_str().unwrap();
        let results = test.get(&Yaml::String("$result".to_string())).unwrap().as_vec().unwrap();
        let result = (results[0].as_str().unwrap().into(), results[1].as_str().unwrap().into());
        vec.push(TestCase::new(name, param, result));
    }

    Ok(vec)
}



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
    fn load_yaml_file() {
        let s =
        "
        base_case:
            $param: '-A INPUT'
            $result:
            - ''
            - 'INPUT'
        ";
        let tests = load_yaml_file(s);
        let result = ResultScheme::new("", "INPUT");
        let valid = vec![TestCase {name: "base_case".to_string(), param: "-A INPUT".to_string(), result: result}];
        assert_eq!(tests, Ok(valid));
    }
    
    #[test]
    fn chan_test() {
        let action = token("A");
        let arg = "-A INPUT";
        let result = action(arg);
        assert_eq!(result, Ok(("", "INPUT")));

        let arg = "-A INPUT -j LOG --log-prefix \"hello guys\"";
        let result = action(arg);
        assert_eq!(result, Ok((" -j LOG --log-prefix \"hello guys\"", "INPUT")));

        let arg = "-A INPUT dfd -j LOG --log-prefix \"hello guys\"";
        let result = action(arg);
        assert_eq!(result, Ok((" -j LOG --log-prefix \"hello guys\"", "INPUT dfd")));

        
        let arg = "-A INPUT ! -s 10.0.0.56/30";
        let result = action(arg);
        assert_eq!(result, Ok((" ! -s 10.0.0.56/30", "INPUT")));
    }
}


fn take_until_eof(s: &str) -> IResult<&str, &str>{
    alt(
        (
            take_until(" ! "),
            take_until(" -"),
            rest
        )
    )(s) 
}


#[allow(dead_code)]
fn token(arg: &'static str) -> impl Fn(&str) ->  IResult<&str, &str>{
    move |input: &str | {
        let dash =  many_m_n(1, 2,char('-'));
        let (other, (neg, _,  _, _, _, res)) = (opt(tag(" ! ")),  space0, dash, tag(arg), char(' '), take_until_eof).parse(input)?;
        
        Ok((other, res))
    }
}