use nom::{
    branch::alt,
    bytes::complete::{tag, take, take_until},
    character::complete::{alpha1, line_ending, not_line_ending, space1, u16},
    combinator::{eof, map, map_parser, not, opt, peek, recognize, rest_len, value, verify},
    multi::{many1, separated_list1},
    sequence::{pair, preceded, separated_pair, terminated, tuple},
    IResult, Parser,
};
use serde_derive::Serialize;
use std::cmp;
use std::str::FromStr;

use d::SingleIntOperator;
use domain as d;
use domain::BuildActionSetting;

#[derive(Debug, PartialEq, Eq)]
pub struct ParseEnum2Error; // TODO нормальное название

#[cfg(test)]
mod tests {
    use super::*;
    use tester::tester;

    #[tester("acl.toml")]
    fn test_rule(arg: &str) -> IResult<&str, d::ACLRule> {
        let v = vec!["MY_CHAIN"];
        rule(arg, &v)
    }

    #[tester("parser.toml")]
    fn test_parser(arg: &str) -> IResult<&str, ACLRule> {
        parser(arg, |_| false)
    }

    #[tester("protocol.toml")]
    fn test_protocol(arg: &str) -> IResult<&str, d::StringOperator> {
        protocol(arg)
    }

    #[tester("protocol_number.toml")]
    fn test_protocol_number(arg: &str) -> IResult<&str, d::IntOperator> {
        protocol_number(arg)
    }

    #[test]
    fn test_flag() {
        assert_eq!(TCPFlagsParser::parse_item("SYN").unwrap(), ("", "SYN"));
        assert_eq!(TCPFlagsParser::flags("SYN").unwrap(), ("", vec!["SYN"]));
        assert_eq!(
            TCPFlagsParser::flags("FIN,SYN,ACK").unwrap(),
            ("", vec!["FIN", "SYN", "ACK"])
        )
    }

    #[test]
    fn test_until_eof() {
        let (remaining, result) = until_eof("").unwrap();
        assert_eq!(remaining, "");
        assert_eq!(result, "");

        let (remaining, result) =
            until_eof("-A INPUT -s 10.0.0.12/32 -j DROP ! --tcp-flags FIN,SYN,ACK ACK").unwrap();
        assert_eq!(
            remaining,
            " -s 10.0.0.12/32 -j DROP ! --tcp-flags FIN,SYN,ACK ACK"
        );
        assert_eq!(result, "-A INPUT");

        let (remaining, result) =
            until_eof("-A INPUT ! -s 10.0.0.12/32 -j DROP ! --tcp-flags FIN,SYN,ACK ACK").unwrap();
        assert_eq!(
            remaining,
            " ! -s 10.0.0.12/32 -j DROP ! --tcp-flags FIN,SYN,ACK ACK"
        );
        assert_eq!(result, "-A INPUT");

        let (remaining, result) = until_eof("-A\ndf").unwrap();
        assert_eq!(remaining, "\ndf");
        assert_eq!(result, "-A");

        let (remaining, result) = until_eof("\ndf").unwrap();
        assert_eq!(remaining, "\ndf");
        assert_eq!(result, "");
    }

    #[test]
    fn test_unknown_part() {
        let (remaining, result) = unknown_part(" ").unwrap();
        assert_eq!(remaining, "");
        assert_eq!(result, " ");

        let (remaining, result) =
            unknown_part(" --match-set BlockedHosts dst,dst -j DROP").unwrap();
        assert_eq!(remaining, " -j DROP");
        assert_eq!(result, " --match-set BlockedHosts dst,dst");

        let (remaining, result) = unknown_part(" --match-set BlockedHosts dst,dst").unwrap();
        assert_eq!(remaining, "");
        assert_eq!(result, " --match-set BlockedHosts dst,dst");

        let (remaining, result) = unknown_part(" --log-ip-options\ns").unwrap();
        assert_eq!(remaining, "\ns");
        assert_eq!(result, " --log-ip-options");

        // точки останова
        // let result = unknown_part("");
        // assert_eq!(remaining, "");
        // assert_eq!(result, "");

        // let result = unknown_part("\ns");
        // assert_eq!(remaining, "\ns");
        // assert_eq!(result, "");
    }
}

fn until_eof(s: &str) -> IResult<&str, &str> {
    // тут лучше взять регулярку наверное

    let res1 = map_parser(
        peek(take_until::<&str, &str, nom::error::Error<&str>>(" !")), // peek клонирует s: &str
        rest_len, // обычный len  только обернутый в trait InputLength
    )
    .parse(s);
    let res2 = map_parser(
        peek(take_until::<&str, &str, nom::error::Error<&str>>(" -")), // внутри take_until std str.find обернутый в FindSubstring
        rest_len,
    )
    .parse(s);

    match (res1, res2) {
        (Ok((_, len1)), Ok((_, len2))) => take(cmp::min(len1, len2)).parse(s),
        (Ok((_, len1)), Err(_)) => take(len1).parse(s),
        (Err(_), Ok((_, len2))) => take(len2).parse(s),
        (Err(_), Err(_)) => not_line_ending.parse(s),
    }
}

fn name(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded(tuple((tag(arg), space1)), until_eof).parse(input)
}

fn strip_value(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded(strip_tag(arg), until_eof).parse(input)
}

fn rstrip_tag(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded(space1, tag(arg)).parse(input)
}

fn strip_tag(arg: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| preceded(space1, terminated(tag(arg), space1)).parse(input)
}

fn unknown_part(input: &str) -> IResult<&str, &str> {
    not(alt((eof, line_ending))).parse(input)?;

    recognize(pair(opt(alt((tag(" -"), tag(" !")))), until_eof)).parse(input)
}

#[derive(Serialize, Clone, PartialEq)]
struct Negative(bool);
impl Negative {
    fn parse(s: &str) -> IResult<&str, Self> {
        map(opt(rstrip_tag("!")), |value| Self(value.is_some())).parse(s)
    }
}

impl d::RangeIntOperator for Negative {
    fn range(&self) -> d::OperatorType {
        match self.0 {
            true => d::OperatorType::NotRange,
            false => d::OperatorType::RANGE,
        }
    }
}

impl d::SingleIntOperator for Negative {
    fn single(&self) -> d::OperatorType {
        match self.0 {
            true => d::OperatorType::NEQ,
            false => d::OperatorType::EQ,
        }
    }
}

fn single_operator(s: &str) -> IResult<&str, d::OperatorType> {
    map(Negative::parse, |value| value.single()).parse(s)
}

enum SingleOrRangeInt {
    Single(u16),
    Range(u16, u16),
}
impl SingleOrRangeInt {
    fn parse(sep: &'static str) -> impl Fn(&str) -> IResult<&str, Self> {
        move |input: &str| {
            alt((
                map(u16::<_, nom::error::Error<&str>>, |value| {
                    Self::Single(value)
                }),
                map(separated_pair(u16, tag(sep), u16), |(f, s)| {
                    Self::Range(f, s)
                }),
            ))
            .parse(input)
        }
    }
}

struct PortParser;

impl PortParser {
    fn build<O>(operator: O, value: SingleOrRangeInt) -> d::IntOperator
    where
        O: d::SingleIntOperator + d::RangeIntOperator,
    {
        match value {
            SingleOrRangeInt::Single(v) => d::IntOperator::new(operator.single(), vec![v]),
            SingleOrRangeInt::Range(f, s) => d::IntOperator::new(operator.range(), vec![f, s]),
        }
    }
    fn port(s: &str) -> IResult<&str, SingleOrRangeInt> {
        SingleOrRangeInt::parse(":").parse(s)
    }

    //  IntOperator --sport 500:600 --dport 45
    fn parse_single(arg: &'static str) -> impl Fn(&str) -> IResult<&str, d::IntOperator> {
        move |input: &str| {
            let value = preceded(strip_tag(arg), Self::port);
            let parser = pair(Negative::parse, value);

            map(parser, |(operator, value)| Self::build(operator, value)).parse(input)
        }
    }
    // ! --ports 50,300:400
    // --ports 50
    fn parse_vec(arg: &'static str) -> impl Fn(&str) -> IResult<&str, Vec<d::IntOperator>> {
        move |input: &str| {
            let ports = separated_list1(tag(","), Self::port);
            let tag = preceded(strip_tag(arg), ports);
            let parser = pair(Negative::parse, tag);

            alt((
                map(parser, |(operator, value)| {
                    value
                        .into_iter()
                        .map(|i| Self::build(operator.clone(), i))
                        .collect()
                }),
                map(Self::parse_single(arg), |value| vec![value]),
            ))
            .parse(input)
        }
    }
}

// --tcp-flags

static TCP_FLAGS_ALL: [&str; 6] = ["SYN", "ACK", "FIN", "RST", "URG", "PSH"];

struct TCPFlagsParser;
impl TCPFlagsParser {
    fn parse_all(s: &str) -> IResult<&str, Vec<&str>> {
        let mut res: Vec<&str> = Vec::with_capacity(6);
        res.extend(TCP_FLAGS_ALL);
        tag("ALL").parse(s).map(|(i, _)| (i, res))
    }

    fn parse_item(s: &str) -> IResult<&str, &str> {
        verify(alpha1, |value| TCP_FLAGS_ALL.contains(value)).parse(s)
    }

    fn flags(s: &str) -> IResult<&str, Vec<&str>> {
        alt((
            Self::parse_all,
            value(vec![], tag("NONE")),
            separated_list1(tag(","), Self::parse_item),
            map(Self::parse_item, |v| vec![v]),
        ))
        .parse(s)
    }

    // _____________ 1    // 2
    //  --tcp-flags FIN,SYN,ACK ACK
    // ! --tcp-flags FIN,SYN,ACK ACK
    fn parse(s: &str) -> IResult<&str, (d::StringOperator, d::StringOperator)> {
        map(
            pair(
                single_operator,
                preceded(
                    strip_tag("--tcp-flags"),
                    separated_pair(Self::flags, space1, Self::flags),
                ),
            ),
            |(operator, value)| {
                let values: Vec<&str>;

                if operator == d::OperatorType::EQ {
                    values = value
                        .0
                        .into_iter()
                        .filter(|x| !value.1.contains(x))
                        .collect()
                } else {
                    values = TCP_FLAGS_ALL
                        .into_iter()
                        .filter(|x| !value.0.contains(x))
                        .collect()
                }

                let first = d::StringOperator::new(d::OperatorType::NEQ, values);
                let second: domain::StringOperator<'_> =
                    d::StringOperator::new(d::OperatorType::EQ, value.1);
                (first, second)
            },
        )
        .parse(s)
    }
}

fn protocol(s: &str) -> IResult<&str, d::StringOperator> {
    let cond = alt((tag("0"), tag("all")));
    let ip = nom::combinator::value("ip", preceded(strip_tag("-p"), cond));

    let value = preceded(strip_tag("-p"), alpha1);

    map(
        pair(single_operator, alt((ip, value))),
        |(operator, value)| d::StringOperator::new(operator, vec![value]),
    )
    .parse(s)
}

fn protocol_number(s: &str) -> IResult<&str, d::IntOperator> {
    let value = preceded(strip_tag("-p"), verify(u16, |value| *value != 0));

    map(pair(single_operator, value), |(operator, value)| {
        d::IntOperator::new(operator, vec![value])
    })
    .parse(s)
}

enum Token<'a> {
    Action(d::ActionType),
    ActionSetting(d::ActionSetting<'a>),
    Option(&'a str),
    Name(&'a str),
    Protocol(d::StringOperator<'a>),
    ProtocolNumber(d::IntOperator),
    SourcePorts(Vec<d::IntOperator>),
    DestinationPorts(Vec<d::IntOperator>),
    Ports(Vec<d::IntOperator>),
    Error(&'a str),
    ActionModifier(d::ActionSetting<'a>),
    TCPFlags((d::StringOperator<'a>, d::StringOperator<'a>)),
}

#[derive(Serialize)]
struct ActionModifiers<'a>(Vec<d::ActionSetting<'a>>);
impl<'a> ActionModifiers<'a> {
    fn push(&mut self, item: d::ActionSetting<'a>) {
        if item.is_type(d::ActionType::LogLevel) {
            self.0[0] = item
        } else {
            self.0.push(item)
        }
    }
}

impl Default for ActionModifiers<'_> {
    fn default() -> Self {
        Self(vec![d::ActionSetting::new(
            d::ActionType::LogLevel,
            "warning",
        )])
    }
}

impl<'a> d::Builder for ActionModifiers<'a>  {
    type Result = Vec<d::ActionSetting<'a>>;
    fn build(self) -> Self::Result {
        self.0
    } 
}

// представление правила в плоской структуре
#[derive(Serialize)]
struct ACLRule<'a> {
    action_settings: BuildWrapper<d::ActionSetting<'a>>,
    action_modifiers: ActionModifiers<'a>,
    errors: Vec<&'a str>,
    name: Option<&'a str>,
    protocol: Option<d::StringOperator<'a>>,
    protocol_number: Option<d::IntOperator>,
    sports: Vec<d::IntOperator>,
    dports: Vec<d::IntOperator>,
    tcp_flags: Option<(d::StringOperator<'a>, d::StringOperator<'a>)>,
    action: Option<d::ActionType>,
    option: Option<&'a str>,
    is_log: bool
}
impl<'a> ACLRule<'a> {
    fn new() -> Self {
        Self {
            action_modifiers: Default::default(),
            errors: Vec::new(),
            action_settings: BuildWrapper(None),
            action: None,
            option: None,
            name: None,
            protocol: None,
            protocol_number: None,
            sports: Vec::new(),
            dports: Vec::new(),
            tcp_flags: None,
            is_log: false
        }
    }

    fn add(&mut self, token: Token<'a>) {
        match token {
            Token::Error(v) => self.errors.push(v),
            Token::ActionSetting(v) => self.action_settings = BuildWrapper(Some(v)),
            Token::Action(v) => self.action = {
                if v == d::ActionType::LOG {
                    self.is_log = true
                }
                Some(v)
            },
            Token::Option(v) => self.option = Some(v),
            Token::ActionModifier(v) => self.action_modifiers.push(v),
            Token::Name(v) => self.name = Some(v),
            Token::Protocol(v) => self.protocol = Some(v),
            Token::ProtocolNumber(v) => self.protocol_number = Some(v),
            Token::Ports(v) => {
                // let mut clone_v: Vec<_> = Vec::with_capacity(v.len());
                // clone_v.copy_from_slice(&v);
                // self.sports.extend(clone_v);
                self.dports.extend(v);
            }
            Token::SourcePorts(v) => self.sports.extend(v),
            Token::DestinationPorts(v) => self.dports.extend(v),
            Token::TCPFlags(v) => self.tcp_flags = Some(v),
        }
    }

    fn build(self) {
        

    }
}

impl<'a> d::Builder for ACLRule<'a> {
    type Result = d::ACLRule<'a>;
    fn build(self) -> Self::Result { // TODO для типов с default убрать Option
        let mut action_bulder = ActionSettingBuilder::default();
        action_bulder.action(self.action).option(self.option);

        let mut acl_rule = ACLRuleBuilder::default();
        acl_rule.action(action_bulder).action(self.action_settings); //  ActionSetting можно создать из двух объектов -g и -j
        self.is_log.then(||acl_rule.action_modifiers(self.action_modifiers));

        acl_rule.build()
        

    }
    
}

fn parser<F>(input: &str, is_user_chain: F) -> IResult<&str, ACLRule>
where
    F: Fn(&str) -> bool,
{
    map(
        many1(alt((
            map(name("-A"), Token::Name),
            map(verify(strip_value("-j"), is_user_chain), |value| {
                Token::ActionSetting(d::ActionSetting::new(d::ActionType::JUMP, value))
            }),
            map(
                verify(strip_value("-j"), |value| {
                    d::ActionType::from_str(value).is_ok()
                }),
                |value| Token::Action(d::ActionType::from_str(value).unwrap()),
            ),
            map(strip_value("--reject-with"), Token::Option),
            map(strip_value("-g"), |value| {
                Token::ActionSetting(d::ActionSetting::new(d::ActionType::GOTO, value))
            }),
            map(strip_value("--log-level"), |value| {
                Token::ActionModifier(d::ActionSetting::new(d::ActionType::LogLevel, value))
            }),
            map(strip_value("--log-prefix"), |value| {
                Token::ActionModifier(d::ActionSetting::new(d::ActionType::LogPrefix, value))
            }),
            map(rstrip_tag("--log-tcp-sequence"), |_| {
                Token::ActionModifier(d::ActionSetting::new(d::ActionType::LogTCPSequence, ""))
            }),
            map(rstrip_tag("--log-tcp-options"), |_| {
                Token::ActionModifier(d::ActionSetting::new(d::ActionType::LogTCPOptions, ""))
            }),
            map(rstrip_tag("--log-ip-options"), |_| {
                Token::ActionModifier(d::ActionSetting::new(d::ActionType::LogIPOptions, ""))
            }),
            map(PortParser::parse_vec("--ports"), |value| {
                Token::Ports(value)
            }),
            map(
                alt((
                    PortParser::parse_vec("--sports"),
                    map(PortParser::parse_single("--sport"), |value| vec![value]),
                )),
                Token::SourcePorts,
            ),
            map(
                alt((
                    PortParser::parse_vec("--dports"),
                    map(PortParser::parse_single("--dport"), |value| vec![value]),
                )),
                Token::DestinationPorts,
            ),
            map(protocol, Token::Protocol),
            map(protocol_number, Token::ProtocolNumber),
            map(TCPFlagsParser::parse, Token::TCPFlags),
            map(unknown_part, Token::Error),
        ))),
        |items| {
            let mut rule = ACLRule::new();
            items.into_iter().for_each(|i| rule.add(i));
            rule
        },
    )
    .parse(input)
}

#[derive(Serialize)]
struct ActionSettingBuilder<'a> {
    action: Option<d::ActionType>,
    option: &'a str,
} // TODO derive_builder

// TODO сделать макросом
impl<'a> BuildActionSetting<'a> for ActionSettingBuilder<'a> {
    fn action(&mut self, action: Option<d::ActionType>) -> &mut Self {
        self.action = action;
        self
    }
    fn option(&mut self, option: Option<&'a str>) -> &mut Self {
        if let Some(v) = option {
            self.option = v;
        }
        self
    }
}

impl Default for ActionSettingBuilder<'_> {
    fn default() -> Self {
        Self {
            action: None,
            option: "",
        }
    }
}

impl<'a> d::OptionBuilder for ActionSettingBuilder<'a> {
    type Result = d::ActionSetting<'a>;
    fn build(self) -> Option<Self::Result> {
        self.action
            .and_then(|v| Some(d::ActionSetting::new(v, self.option)))
    }
}

#[derive(Serialize)]
struct BuildWrapper<T>(std::option::Option<T>);

impl<T> d::OptionBuilder for BuildWrapper<T> {
    type Result = T;
    fn build(self) -> Option<Self::Result> {
        self.0
    }
}

#[derive(Serialize)]
struct ACLRuleBuilder<'a> {
    action: d::ActionSetting<'a>,
    action_modifiers: Vec<d::ActionSetting<'a>>
} // TODO derive_builder

impl<'a> ACLRuleBuilder<'a> {
    // для каждого типа T который реализует Builder<Result = domain::ActionSetting> будет создана своя версия action<конкретный тип>
    // тип T дропается в build()
    // все билдеры одноразовые
    fn action<T>(&mut self, action: T) -> &mut Self
    where
        T: d::OptionBuilder<Result = d::ActionSetting<'a>>,
    {
        if let Some(v) = action.build() {
            self.action = v
        }
        self
    }
    fn action_modifiers<T>(&mut self, values: T) -> &mut Self
    where 
        T: d::Builder<Result = Vec<d::ActionSetting<'a>>>,
    {
        self.action_modifiers = values.build();
        self
    }

}

impl<'a> d::Builder for ACLRuleBuilder<'a>  {
    type Result = d::ACLRule<'a>;
    fn build(self) -> Self::Result {
        let  normalized_action = self.action.normalized_action().ok();
        d::ACLRule::new(vec![self.action], vec![normalized_action], self.action_modifiers)
}
}

impl Default for ACLRuleBuilder<'_> {
    fn default() -> Self {
        Self {
            action: d::ActionSetting::new(d::ActionType::PASS, ""),
            action_modifiers: vec![]
        }
    }
}

pub fn rule<'a>(input: &'a str, user_chains: &Vec<&'a str>) -> IResult<&'a str, d::ACLRule<'a>> {
    let (remain, (name, rule)) = parser(input, |v| user_chains.contains(&v))
        .map(|(remain, tokens)| (remain, tokens.build()))?;

    Ok((remain, rule))
}
