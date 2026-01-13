#[cfg(test)]
mod tests {
    use common::ip_parser;
    use domain::ip::IPAddress;

    #[test]
    fn test_ip_address() {
        let (remain, ip) = ip_parser("127.0.0.1").unwrap();
        assert_eq!(remain, "");
        let res = IPAddress::to_ip_address(ip, 28).unwrap();
        let r: String = toml::to_string(&res).unwrap();
        assert_eq!(
            r,
            "Prefix = 28

[Address]
Address = \"127.0.0.1\"
Version = 4

[NetworkID]
Address = \"127.0.0.0\"
Version = 4
"
        )
    }

    #[test]
    fn test_ip_address2() {
        let (remain, ip) = ip_parser("127.0.0.1").unwrap();
        assert_eq!(remain, "");
        let res = IPAddress::to_ip_address(ip, 32).unwrap();
        let r: String = toml::to_string(&res).unwrap();
        assert_eq!(
            r,
            "Prefix = 32

[Address]
Address = \"127.0.0.1\"
Version = 4

[NetworkID]
Address = \"127.0.0.1\"
Version = 4
"
        )
    }
}
