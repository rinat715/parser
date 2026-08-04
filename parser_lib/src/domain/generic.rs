use macros::{ToDict, ToStr};
use serde_derive::Serialize;
use smol_str::SmolStr;

pub trait EnumToStr {
    fn to_str(&self) -> &str;
}

pub fn bool_operator<T>(operator: impl Into<bool>, value: Tuple<T>) -> Operator<Bool, T> {
    let operator = Bool(operator.into());
    Operator { operator, value }
}

pub fn bool_operator_singe<T>(operator: impl Into<bool>, value: T) -> Operator<Bool, T> {
    let operator = Bool(operator.into());
    let value = Tuple::Single(value);
    Operator { operator, value }
}

#[derive(Serialize, Default, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(transparent)]
pub struct Str(SmolStr);
impl Str {
    pub fn new(value: &str) -> Self {
        Self(SmolStr::new(value))
    }

    pub fn some(value: &str) -> Option<Self> {
        Some(Self::new(value))
    }

    pub const fn new_static(value: &'static str) -> Self {
        Self(SmolStr::new_static(value))
    }
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl PartialEq<&str> for Str {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Str> for &str {
    fn eq(&self, other: &Str) -> bool {
        *self == other.0
    }
}

#[derive(Clone)]
pub enum Tuple<T> {
    Single(T),
    Pair(T, T),
}

impl<T> Tuple<T> {
    pub fn is_single(&self) -> bool {
        match self {
            Tuple::Single(_) => true,
            Tuple::Pair(_, _) => false,
        }
    }
}

#[derive(Clone, ToDict)]
pub struct Operator<T, T1> {
    #[serialize(rename = "Operator")]
    pub operator: T,
    #[serialize(rename = "Values")]
    pub value: Tuple<T1>,
}

#[derive(Clone, PartialEq, ToStr)]
pub struct Bool(pub bool);

impl EnumToStr for Bool {
    fn to_str(&self) -> &'static str {
        match self.0 {
            true => "eq",
            false => "neq",
        }
    }
}

impl PartialEq<bool> for Bool {
    fn eq(&self, other: &bool) -> bool {
        self.0 == *other
    }
}

impl From<bool> for Bool {
    fn from(value: bool) -> Self {
        Self(value)
    }
}

#[derive(Clone, ToStr)]
pub struct Range(pub bool);

impl EnumToStr for Range {
    fn to_str(&self) -> &'static str {
        match self.0 {
            true => "range",
            false => "nrange",
        }
    }
}

#[derive(Clone, ToDict)]
pub struct OperatorVec<T, T1> {
    #[serialize(rename = "Operator")]
    pub operator: T,
    #[serialize(rename = "Values")]
    pub values: Vec<T1>,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum Value<T> {
    Value(T),
    Error(Str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn str_eq() {
        let s = Str::new("LOG");
        assert_eq!(s, "LOG")
    }

    #[test]
    fn empty_str() {
        let s = Str::new("");
        assert_eq!(s, "")
    }
}
