use serde::{
    Serialize,
    ser::{SerializeMap, Serializer},
};

use serde::ser::SerializeStruct;

pub trait SerializeDict {
    fn serialize_dict_entries<S>(&self, serialize_map: S) -> Result<S, S::Error>
    where
        S: SerializeMap;
}

impl Serialize for crate::domain::IPProtocolOptions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::ANY => Self::ANY_OPERATOR.serialize(serializer),
            Self::LooseSourceRouting => Self::LOOSE_SOURCE_ROUTING_OPERATOR.serialize(serializer),
            Self::NoRecordRoute => Self::NO_RECORD_ROUTE_OPERATOR.serialize(serializer),
            Self::NoRouterAlert => Self::NO_ROUTER_ALERT_OPERATOR.serialize(serializer),
            Self::NoSourceRouting => Self::NO_SOURCE_ROUTING_OPERATOR.serialize(serializer),
            Self::NoTimestamp => Self::NO_TIMESTAMP_OPERATOR.serialize(serializer),
            Self::RecordRoute => Self::RECORD_ROUTE_OPERATOR.serialize(serializer),
            Self::RouterAlert => Self::ROUTER_ALERT_OPERATOR.serialize(serializer),
            Self::StrictSourceRouting => Self::STRICT_SOURCE_ROUTING_OPERATOR.serialize(serializer),
            Self::Timestamp => Self::TIMESTAMP_OPERATOR.serialize(serializer),
        }
    }
}

impl Serialize for crate::domain::ProtocolSetting {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?; // TODO 2?
        match &self.0 {
            crate::domain::Protocol::TCP(v) => {
                map = v.serialize_dict_entries(map)?;
            }

            crate::domain::Protocol::UDP(v) => {
                map = v.serialize_dict_entries(map)?;
            }
            crate::domain::Protocol::Number(v) => {
                map.serialize_entry("ProtocolNumber", v)?;
            }
            crate::domain::Protocol::String(v) => {
                map.serialize_entry("Protocol", v)?;
            }
        }

        if self.1.is_some() {
            map.serialize_entry("IPv4Options", &self.1)?;
        };

        map.end()
    }
}

impl<T, T1> Serialize for crate::domain::Rule<T, T1>
where
    T: crate::domain::serialize::SerializeDict,
    T1: crate::domain::serialize::SerializeDict,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(3))?;
        map = self.0.serialize_dict_entries(map)?;
        map = self.1.serialize_dict_entries(map)?;
        map = self.2.serialize_dict_entries(map)?;
        map.end()
    }
}

impl Serialize for crate::domain::EndpointSetting {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("EndpointSetting", 1)?;
        match self {
            Self::IPOperator(v) => {
                state.serialize_field("Address", v)?;
            }
        }

        state.end()
    }
}

impl<T> Serialize for crate::domain::generic::Tuple<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Single(v) => (v,).serialize(serializer),
            Self::Pair(f, s) => (f, s).serialize(serializer),
        }
    }
}

#[cfg(test)]
mod tests {
    use smol_str::SmolStr;

    #[test]
    fn serialize_empty_str() {
        let s = crate::domain::Str::new("");

        let actual = yaml_serde::to_string(&s).unwrap();

        let expected = "''\n";

        assert_eq!(
            expected,
            actual,
            "{}",
            diff::Diff::new("None", "serialize_empty_str", &actual, &expected)
        )
    }

    #[test]
    fn serialize_empty_str2() {
        let s = SmolStr::new("");

        let actual = yaml_serde::to_string(&s).unwrap();

        let expected = "''\n";

        assert_eq!(
            expected,
            actual,
            "{}",
            diff::Diff::new("None", "serialize_empty_str2", &actual, &expected)
        )
    }
}
