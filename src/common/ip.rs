use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{char, hex_digit1, u8},
    combinator::{map, map_res},
    multi::fold_many1,
    sequence::{terminated, tuple},
    IResult, Parser,
};

use crate::domain as d;

const LONGEST_IPV6_ADDR: &str = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"; // из std net

fn _ip4(input: &str) -> IResult<&str, u8> {
    terminated(u8, char('.')).parse(input)
}

fn ip4(input: &str) -> IResult<&str, d::IP> {
    let parser = tuple((_ip4, _ip4, _ip4, u8));

    map(parser, |res| d::IP::new_ip4(res.0, res.1, res.2, res.3)).parse(input)
}

fn ip6(input: &str) -> IResult<&str, d::IP> {
    let item_parser = alt((hex_digit1, tag(":")));

    let parser = fold_many1(
        item_parser,
        || String::with_capacity(LONGEST_IPV6_ADDR.len()),
        |mut acc: String, item| {
            acc.push_str(item);
            acc
        },
    );

    map_res(parser, |r| d::IP::parse_ip6(&r)).parse(input) // MapRes а AddrParseError подавится
}

pub fn ip_parser(input: &str) -> IResult<&str, d::IP> {
    alt((ip4, ip6)).parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4() {
        let (remain, res) = ip_parser("127.0.0.1").unwrap();
        assert_eq!(remain, "");
        assert_eq!(res, d::IP::new_ip4(127, 0, 0, 1));

        let (remain, res) = ip_parser("169.254.50.30").unwrap();
        assert_eq!(remain, "");
        assert_eq!(res, d::IP::new_ip4(169, 254, 50, 30));
    }

    #[test]
    fn test_ipv6() {
        let (remain, res) = ip_parser("123::250:56ff:fea6:430e").unwrap();
        assert_eq!(remain, "");
        assert_eq!(
            res,
            d::IP::new_ip6(0x123, 0, 0, 0, 0x250, 0x56ff, 0xfea6, 0x430e)
        );

        let (remain, res) = ip_parser("::1 dfdfdf").unwrap();
        assert_eq!(remain, " dfdfdf");
        assert_eq!(res, d::IP::new_ip6(0, 0, 0, 0, 0, 0, 0, 0x1));

        let (remain, res) = ip_parser("2001:d00::").unwrap();
        assert_eq!(remain, "");
        assert_eq!(res, d::IP::new_ip6(0x2001, 0xd00, 0, 0, 0, 0, 0, 0));

        let result = ip_parser(":");

        assert_eq!(
            result,
            Err(nom::Err::Error(nom::error::Error::new(
                ":",
                nom::error::ErrorKind::MapRes
            )))
        );

        let result = ip_parser("Z");

        assert_eq!(
            result,
            Err(nom::Err::Error(nom::error::Error::new(
                "Z",
                nom::error::ErrorKind::Many1
            )))
        );

        let result = ip_parser("");

        assert_eq!(
            result,
            Err(nom::Err::Error(nom::error::Error::new(
                "",
                nom::error::ErrorKind::Many1
            )))
        );
    }
}
