use macros::ToDict;
use pyo3::prelude::*;

use serde_derive::Serialize;

use crate::domain::generic::{Bool, Operator};
use crate::domain::{IPAddress, Range, Str, Tuple, generic, single_operator};

// // https://docs.rs/pyo3/0.15.2/pyo3/prelude/struct.Py.html#method.from_borrowed_ptr
// в чем разница между into_py и into как будто оба
// unsafe { PyObject::from_borrowed_ptr(py, self.as_ptr()) }
// py достается из самого объекта
// unsafe { Python::assume_gil_acquired()ss
// unsafe { Py::from_borrowed_ptr(obj.py(), obj.as_ptr()) }
//

pub type StringOperator = generic::OperatorVec<Bool, Str>;

impl StringOperator {
    pub fn new(operator_type: impl Into<Bool>, values: Vec<Str>) -> Self {
        Self {
            operator: operator_type.into(),
            values,
        }
    }

    pub fn single(operator_type: impl Into<Bool>, value: &str) -> Self {
        Self::new(operator_type, vec![Str::new(value)])
    }
}

pub struct StringOperatorBuilder {
    operator: Bool,
}
impl StringOperatorBuilder {
    pub fn new(operator: impl Into<Bool>) -> Self {
        Self {
            operator: operator.into(),
        }
    }

    pub fn from_value(&self, value: &str) -> StringOperator {
        StringOperator::new(self.operator.clone(), vec![Str::new(value)])
    }
}

type Network = Operator<Bool, crate::domain::IPAddress>;
type IPRange = Operator<Range, crate::domain::IPAddress>;
type IP = Operator<Bool, crate::domain::IPAddress>;

#[derive(Serialize, Clone)]
#[serde(untagged)]
enum IPOperatorPrivate {
    Network(Network),
    IPRange(IPRange),
    IP(IP),
}

fn range_ip_operator(
    operator: bool,
    f: crate::domain::IPAddress,
    s: crate::domain::IPAddress,
) -> IPRange {
    let operator = Range(operator);
    let value = Tuple::Pair(f, s);
    Operator { operator, value }
}

impl IPOperatorPrivate {
    fn ip4_address(operator: impl Into<bool>, ip: crate::domain::IP, prefix: u8) -> Self {
        Self::Network(single_operator(
            operator.into(),
            IPAddress::new_assert(ip, prefix),
        ))
    }
    fn ip4_address_32(operator: impl Into<bool>, ip: crate::domain::IP) -> Self {
        Self::IP(single_operator(
            operator.into(),
            IPAddress::new_assert(ip, 32),
        ))
    }
    fn ip_range(
        operator: impl Into<bool>,
        pair_ip: (crate::domain::IP, crate::domain::IP),
    ) -> Self {
        Self::IPRange(range_ip_operator(
            operator.into(),
            IPAddress::new_assert(pair_ip.0, 32),
            IPAddress::new_assert(pair_ip.1, 32),
        ))
    }
}

#[derive(Serialize, Clone)]
#[serde(transparent)]
pub struct IPOperator(IPOperatorPrivate);

impl IPOperator {
    pub fn ip4_address(operator: impl Into<bool>, ip: crate::domain::IP, prefix: u8) -> Self {
        Self(IPOperatorPrivate::ip4_address(operator, ip, prefix))
    }
    pub fn ip_range(
        operator: impl Into<bool>,
        ip_pair: (crate::domain::IP, crate::domain::IP),
    ) -> Self {
        Self(IPOperatorPrivate::ip_range(operator, ip_pair))
    }

    pub fn ip(operator: impl Into<bool>, ip: crate::domain::IP) -> Self {
        Self(IPOperatorPrivate::ip4_address_32(operator, ip))
    }
}

impl<'a> IntoPy<PyObject> for IPOperator {
    fn into_py(self, py: Python) -> PyObject {
        match self.0 {
            IPOperatorPrivate::Network(v) => v.into_py(py),
            IPOperatorPrivate::IPRange(v) => v.into_py(py),
            IPOperatorPrivate::IP(v) => v.into_py(py),
        }
    }
}

#[derive(ToDict, Clone)]
pub struct SetOperator {
    #[serialize(rename = "Operator")]
    operator: Bool,
    #[serialize(rename = "Set")]
    set: Str,
    #[serialize(rename = "Flags")]
    flags: Vec<Str>,
}

impl SetOperator {
    pub fn new(operator: impl Into<Bool>, set: &str, flags: Vec<Str>) -> Self {
        let set = Str::new(set);
        Self {
            operator: operator.into(),
            set,
            flags,
        }
    }
}



