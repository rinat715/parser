use std::iter::once;

use macros::{ToDict, ToStr};
use serde::{
    Serialize as SerializeTrait,
    ser::{SerializeSeq, Serializer},
};
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

#[derive(Clone)]
pub struct NonEmptyVec<T> {
    head: T,
    tail: Vec<T>,
}

impl<T> NonEmptyVec<T> {
    pub fn new(head: T, tail: Vec<T>) -> Self {
        Self { head, tail }
    }

    pub fn first(&self) -> &T {
        &self.head
    }

    pub fn len(&self) -> usize {
        self.tail.len() + 1
    }

    pub fn into_iter(self) -> impl Iterator<Item = T> {
        once(self.head).chain(self.tail.into_iter())
    }
}

impl<T> SerializeTrait for NonEmptyVec<T>
where
    T: serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        seq.serialize_element(&self.head)?;

        for element in &self.tail {
            seq.serialize_element(element)?;
        }
        seq.end()
    }
}

#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use pyo3::types::PyList;

#[cfg(feature = "python")]
impl<'a, T> IntoPy<PyObject> for NonEmptyVec<T>
where
    T: IntoPy<PyObject>,
{
    fn into_py(self, py: Python) -> PyObject {
        let v: Vec<PyObject> = self.into_iter().map(|v| v.into_py(py)).collect();
        let l = PyList::new(py, &v);
        l.into_py(py)
    }
}

#[derive(Clone, ToDict)]
pub struct OperatorVec<T, T1> {
    #[serialize(rename = "Operator")] 
    pub operator: T,
    #[serialize(rename = "Values")]
    pub values: NonEmptyVec<T1>,
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
