use crate::domain as d;

use serde_derive::Serialize;

pub enum ProtocolPart<T> {
    DestinationPorts(Vec<d::PortOperator>),
    Ports(Vec<d::PortOperator>),
    Protocol((T, d::ProtocolType)),
    SourcePorts(Vec<d::PortOperator>),
    TCPFlags((d::FlagOperator, d::FlagOperator)),
    TTL(d::TTL),
    Fragment(d::Fragment),
    DSCP(d::DSCP),
    PacketLength(d::PacketLength),
    IPProtocolOption(d::IPProtocolOptions),
}

pub enum General {
    Source(d::IPOperator),
    Destination(d::IPOperator),
}

pub enum Interface<'a> {
    Value(&'a str),
    Mask(&'a str),
}

#[derive(Serialize)]
pub enum Address {
    Network((d::IP, u8)),
    IP(d::IP),
    Range((d::IP, d::IP)),
}

impl Address {
    pub fn ip_operator<T>(self, operator: T) -> d::IPOperator
    where
        bool: From<T>,
    {
        match self {
            Self::Network((ip, prefix)) => d::IPOperator::ip4_address(operator, ip, prefix),
            Self::IP(ip) => d::IPOperator::ip(operator, ip),
            Self::Range((f, s)) => d::IPOperator::ip_range(operator, (f, s)),
        }
    }
}

pub mod nftables {
    use super::*;

    use crate::nftables::{ActionType, Operator};

    pub enum ACL<'a> {
        Action(ActionType),
        Jump(&'a str),
        Goto(&'a str),
        RejectWith(&'a str),
        LogLevel(d::ActionSetting<ActionType>),
        ActionModifier(d::ActionSetting<ActionType>),
        InterfaceIn((bool, Vec<Interface<'a>>)),
        InterfaceOut((bool, Vec<Interface<'a>>)),
    }

    pub enum NAT<'a> {
        Type(d::nftables::NATType),
        Jump(&'a str),
        Goto(&'a str),
        InterfaceIn((bool, Vec<Interface<'a>>)),
        InterfaceOut((bool, Vec<Interface<'a>>)),
        TranslatedSource((d::IPOperator, Option<d::PortOperator>)),
        TranslatedDestination((d::IPOperator, Option<d::PortOperator>)),
        TranslatedPort(d::PortOperator),
    }

    pub enum Vendor {
        Ctstate(Vec<d::StringOperator>),
        Sets(d::SetOperator),
        NetworkMappedTranslatedAddress(d::IPOperator),
    }

    pub enum Rule<'a, T> {
        Protocol(ProtocolPart<Operator>),
        General(General),
        Extended(T),
        Vendor(Vendor),
        Error(&'a str),
        Space,
    }

    impl<'a, T> Rule<'a, T> {
        pub fn space(_: &'a str) -> Self {
            Rule::Space
        }
    }

    pub type ACLRule<'a> = Rule<'a, ACL<'a>>;
    pub type NATRule<'a> = Rule<'a, NAT<'a>>;
}
