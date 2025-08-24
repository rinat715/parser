#![allow(dead_code)]

use nom::{
    branch::alt,
    bytes::complete::{tag, take, take_until},
    character::complete::{alpha1, line_ending, not_line_ending, space1, u16},
    combinator::{eof, map, map_parser, not, opt, peek, recognize, rest_len, value, verify},
    error::ParseError,
    multi::{fold_many1, separated_list1},
    sequence::{delimited, pair, preceded, separated_pair, terminated, tuple},
    IResult, Parser,
};
use serde::de::value;
use serde_derive::Serialize;

use common::single_or_pair_u16;
use domain as d;
use domain::BuildIntOperator;
use domain::Builder;

type ActionSetting<'a> = d::ActionSetting<'a, ActionType>;

mod tests {
    use super::*;
    use tester::tester;

    #[tester("acl_name.toml")]
    fn test_name(arg: &str) -> IResult<&str, &str> {
        name(arg)
    }

    #[test]
    fn test_rule() {
        let (remain, rule) = rule("100 deny any any any").unwrap();
        assert_eq!(remain, "any any");
        assert_eq!(rule.line_number.unwrap(), 1);
    }
}

// ip access-list ACL_NAME_3\n
// ip access-list ACL_NAME basic\n
// ip access-list 100 extend\n
fn name(s: &str) -> IResult<&str, &str> {
    fn start(s: &str) -> IResult<&str, (&str, &str)> {
        pair(tag("ip access-list"), space1).parse(s)
    }

    let basic = pair(space1, tag("basic"));
    let extend = pair(space1, tag("extend"));

    alt((
        delimited(start, take_until(" "), alt((basic, extend))),
        preceded(start, take_until("\n")),
    ))
    .parse(s)
}

#[derive(Debug, PartialEq, Default, Serialize, Clone)]
enum ActionType {
    PERMIT,
    #[default]
    DENY,
}

impl TryInto<d::NormalizedAction> for ActionType {
    type Error = d::ParseEnumError;

    fn try_into(self) -> Result<d::NormalizedAction, Self::Error> {
        match self {
            Self::PERMIT => Ok(d::NormalizedAction::PERMIT),
            Self::DENY => Ok(d::NormalizedAction::DENY),

            _ => Err(d::ParseEnumError),
        }
    }
}

///
/// line-num
/// {permit | deny}
/// {protocl-name | protocol-number | any}
///
/// {host src-ip-address | src-ip-address wildcard_mask | any}
/// [src-port {[gt {src-port-num } | lt {src-port-num} | range {first-src-port-number last-src-port-number} | eq {src-port-num}]}]
///  
/// {host dst-ip-address | dst-ip-address wildcard_mask | any}
/// [dst-port {[gt {dst-port-num } | lt {dst-port-num } | range {first-dst-port-number last-dst-port-number} | eq {dst-port-num}]}
///  
/// time-range time_range_name [precedence prec-lvl | dscp {dscp-num} | ecn {ecn-num}]  
/// [established]
/// [icmp-type type]
/// [icmp-code code]]

#[derive(Serialize)]
struct ACLRuleBuilder<'a>(d::ACLRule<'a, ActionType>);

impl<'a> ACLRuleBuilder<'a> {
    fn action(&mut self, action: ActionSetting<'a>) -> &mut Self {
        self.0.action = Some(vec![action]);
        self
    }

    fn line_number(&mut self, number: u16) -> &mut Self {
        self.0.line_number = Some(number);
        self
    }
}

impl<'a> d::Builder for ACLRuleBuilder<'a> {
    type Result = d::ACLRule<'a, ActionType>;

    fn build(self) -> Self::Result {
        self.0
    }
}

impl<'a> Default for ACLRuleBuilder<'a> {
    fn default() -> Self {
        let mut rule = d::ACLRule::default();

        rule.action_modifiers = Some(vec![]);
        rule.normalized_action = None;

        Self(rule)
    }
}

// eq 667
//  {[gt {src-port-num } | lt {src-port-num} | range {first-src-port-number last-src-port-number} | eq {src-port-num}]
fn operator(s: &str) -> IResult<&str, d::OperatorType> {
    let gt = value(d::OperatorType::GT, tag("gt"));
    let lt = value(d::OperatorType::LT, tag("lt"));
    let eq = value(d::OperatorType::EQ, tag("eq"));
    let range = value(d::OperatorType::RANGE, tag("range"));

    terminated(alt((gt, lt, eq, range)), space1).parse(s)
}

struct PortParser;
impl PortParser {
    fn port(s: &str) -> IResult<&str, d::SingleOrPair<u16>> {
        single_or_pair_u16(" ").parse(s)
    }

    // dst-port eq 667
    // dst-port range 667 668
    fn parse_single(arg: &'static str) -> impl Fn(&str) -> IResult<&str, d::IntOperator> {
        move |input: &str| {
            let name = terminated(tag(arg), space1);
            let operator = terminated(operator, space1);
            let parser = preceded(name, pair(operator, Self::port));

            map(parser, |(operator, value)| Self::build(operator, value)).parse(input)
        }
    }
}

impl BuildIntOperator for PortParser {}

fn protocol(s: &str) -> IResult<&str, d::Protocol> {
    map(terminated(common::protocol, space1), |value| {
        d::Protocol::new(d::OperatorType::EQ, value)
    })
    .parse(s)
}

// 100 deny any any any
fn rule<'a>(s: &str) -> IResult<&str, d::ACLRule<'a, ActionType>> {
    let mut bulder = ACLRuleBuilder::default();

    let number = terminated(u16, space1); // обязательное

    let deny = value(ActionType::DENY, tag("deny"));
    let permit = value(ActionType::PERMIT, tag("permit"));

    let action = map(terminated(alt((deny, permit)), space1), |v| {
        ActionSetting::new(v, Default::default())
    }); // обязательное

    let (remain, res) = tuple((number, action, protocol)).parse(s)?;

    bulder.line_number(res.0);
    bulder.action(res.1);

    Ok((remain, bulder.build()))
}
