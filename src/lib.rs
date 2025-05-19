use domain::ActionSetting;
use nom::character::complete::not_line_ending;
use nom::character::complete::space0;
use nom::combinator::map;
use nom::multi::many1;
use nom::sequence::preceded;
use nom::Parser;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::space1,
    IResult,
};
mod domain;
use domain as d;
use std::f64::consts::E;
use std::str::FromStr;

#[cfg(test)]
mod tests {
    use super::*;
    use tester::tester;

    #[tester("token_a.toml")]
    fn token_a(arg: &str) -> IResult<&str, &str> {
        token("-A")(arg)
    }

    #[tester("token_g.toml")]
    fn token_goto(arg: &str) -> IResult<&str, domain::ActionSetting> {
        get_goto(arg)
    }
}

fn remove_dash(s: &str) -> IResult<&str, &str> {
    alt((tag("--"), tag("-")))(s)
}

fn until_eof(s: &str) -> IResult<&str, &str> {
    let is_next = alt((take_until(" !"), take_until(" -")));

    alt((is_next, not_line_ending))(s)
}

fn token(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| {
        let (input, _) = space0(input)?;
        let (input, _) = preceded(tag(arg), space1)(input)?;
        until_eof(input)
    }
}

// fn get_action_modifier(arg: &'static str) -> impl Fn(&str) -> IResult<&str, domain::ActionSetting> {
//     move |input: &str| {
//         let mut parser = map(token(arg), |s: &str| domain::ActionSetting ;
//         parser.parse(input)
//     }
// }
struct ActionSettingBuilder<'a>{
    user_chains: Vec<&'a str>
}
impl<'a> ActionSettingBuilder<'a> {
    fn build(&self, action: &'a str, option: &'a str) -> ActionSetting {
        if let Ok(action) = d::ActionType::from_str(action) {
            match action {
                d::ActionType::ACCEPT |
                d::ActionType::DROP |
                d::ActionType::QUEUE|
                d::ActionType::RETURN |
                d::ActionType::LOG => return ActionSetting::new(action, ""),
                d::ActionType::REJECT => return ActionSetting::new(action, option),

                _ => !todo!()
            }
        }

        if self.user_chains.contains(&action) {
            return ActionSetting::new(d::ActionType::JUMP, action)
        }

        ActionSetting::new(domain::ActionType::PASS, "")
        
    }
}




struct Name<'a>(&'a str);
struct Action<'a>(&'a str);
struct Option<'a>(&'a str);

fn name(input: &str) -> IResult<&str, Name> {
    let mut parser = map(token("-A"), |s: &str| Name(s));
    parser.parse(input)
}

fn goto(input: &str) -> IResult<&str, ActionSetting> {
    let mut parser = map(token("-g"), |s: &str| ActionSetting::new(d::ActionType::GOTO, s));
    parser.parse(input)
}

fn jump(input: &str) -> IResult<&str, Action> {
    let mut parser = map(token("-j"), |s: &str| Action(s));
    parser.parse(input)
}

fn reject_with(input: &str) -> IResult<&str, Option> {
    let mut parser = map(token("-reject-with"), |s: &str| Option(s));
    parser.parse(input)
}

enum ResultParser {
    Name,
    ActionSetting,
}

// pub fn rule<'a>(input: &'a str) -> IResult<&str, ACLRule<'a>> {
//     let mut rule: ACLRule = Default::default();

//     //let mut parser: IResult<&str, Vec<ResultParser>> =many1(alt((get_name, get_goto)))(input);

//     Ok((input, rule))
// }
