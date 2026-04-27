use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};
use serde_derive::Serialize;

use crate::domain::ip;

#[derive(Serialize, Clone, PartialEq)]
pub struct OperatorTypeGeneric<T>(pub T);

pub trait BuildOperatorType {
    fn range(&self) -> OperatorType;

    fn single(&self) -> OperatorType;
}

#[derive(Serialize, Clone, PartialEq)]
#[serde(rename_all(serialize = "lowercase", deserialize = "UPPERCASE"))]
pub enum OperatorType {
    EQ,
    NEQ,
    RANGE,
    NotRange,
    GT,
    LT,
    MatchAny,
}

impl<'a> IntoPy<PyObject> for OperatorType {
    fn into_py(self, py: Python) -> PyObject {
        let res = match self {
            Self::EQ => PyString::new(py, "EQ"),
            Self::NEQ => PyString::new(py, "NEQ"),
            Self::RANGE => PyString::new(py, "RANGE"),
            Self::NotRange => PyString::new(py, "NotRange"),
            Self::GT => PyString::new(py, "GT"),
            Self::LT => PyString::new(py, "LT"),
            Self::MatchAny => PyString::new(py, "MatchAny"),
        };
        res.into_py(py)
    }
}

pub enum SingleOrPair<T> {
    Single(T),
    Pair(T, T),
}

#[derive(Serialize, Clone)]
pub struct Operator<T> {
    operator: OperatorType,
    values: Vec<T>,
}

impl<'a, T> Operator<T> {
    pub fn new(operator_type: OperatorType, values: Vec<T>) -> Self {
        Self {
            operator: operator_type,
            values: values,
        }
    }
}

impl<'a, T> IntoPy<PyObject> for Operator<T>
where
    T: IntoPy<PyObject>,
{
    fn into_py(self, py: Python) -> PyObject {
        let l = PyList::new(
            py,
            &[
                ("operator", self.operator.into_py(py)),
                ("values", self.values.into_py(py)),
            ],
        );
        let dict = PyDict::from_sequence(py, l.into()).unwrap();
        dict.into_py(py) // Py_INCREF

    }
}

pub type IntOperator = Operator<u16>;

pub struct IntOperatorBuilder {
    operator: OperatorType,
}
impl IntOperatorBuilder {
    pub fn new(operator: OperatorType) -> Self {
        Self { operator }
    }

    pub fn from_value(&self, value: u16) -> IntOperator {
        IntOperator::new(self.operator.clone(), vec![value])
    }

    pub fn from_list(&self, values: Vec<u16>) -> IntOperator {
        IntOperator::new(self.operator.clone(), values)
    }

    pub fn from_build_operator_type<T>(operator: T, value: SingleOrPair<u16>) -> IntOperator
    where
        T: BuildOperatorType,
    {
        match value {
            SingleOrPair::Single(v) => IntOperator::new(operator.single(), vec![v]),
            SingleOrPair::Pair(f, s) => IntOperator::new(operator.range(), vec![f, s]),
        }
    }
}

// // https://docs.rs/pyo3/0.15.2/pyo3/prelude/struct.Py.html#method.from_borrowed_ptr
// в чем разница между into_py и into как будто оба
// unsafe { PyObject::from_borrowed_ptr(py, self.as_ptr()) }
// py достается из самого объекта
// unsafe { Python::assume_gil_acquired()ss
// unsafe { Py::from_borrowed_ptr(obj.py(), obj.as_ptr()) }
//

pub type StringOperator<'a> = Operator<&'a str>;

impl<'a> StringOperator<'a> {
    pub fn normalize(&self) -> &'a str {
        self.values.first().clone().unwrap()
    }
}

pub struct StringOperatorBuilder {
    operator: OperatorType,
}
impl StringOperatorBuilder {
    pub fn new(operator: OperatorType) -> Self {
        Self { operator }
    }

    pub fn from_value<'a>(&self, value: &'a str) -> StringOperator<'a> {
        StringOperator::new(self.operator.clone(), vec![value])
    }
}

pub type IPOperator = Operator<ip::IPAddress>;

#[derive(Serialize, Clone)]
pub struct SetOperator<'a> {
    operator: OperatorType,
    set: &'a str,
    flags: Vec<&'a str>,
}

impl<'a> SetOperator<'a> {
    pub fn new(operator: OperatorType, set: &'a str, flags: Vec<&'a str>) -> Self {
        Self {
            operator,
            set,
            flags,
        }
    }
}

impl<'a> IntoPy<PyObject> for SetOperator<'a> {
    fn into_py(self, py: Python) -> PyObject {
        let l = PyList::new(
            py,
            &[
                ("Set", self.set.into_py(py)),
                ("Flags", self.flags.into_py(py)),
                ("Operator", self.operator.into_py(py)),
            ],
        );
        let dict = PyDict::from_sequence(py, l.into()).unwrap();
        dict.into_py(py) // Py_INCREF
    }
}
