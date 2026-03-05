use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};
use serde_derive::Serialize;

use nom::{combinator::map, error::ParseError, Parser};

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
        match self {
            Self::EQ => PyString::new(py, "EQ").into_py(py),
            Self::NEQ => PyString::new(py, "NEQ").into_py(py),
            Self::RANGE => PyString::new(py, "RANGE").into_py(py),
            Self::NotRange => PyString::new(py, "NotRange").into_py(py),
            Self::GT => PyString::new(py, "GT").into_py(py),
            Self::LT => PyString::new(py, "LT").into_py(py),
            Self::MatchAny => PyString::new(py, "MatchAny").into_py(py),
        }
    }
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
        let dict = PyDict::new(py);
        dict.set_item::<PyObject, PyObject>("operator".into_py(py), self.operator.into_py(py))
            .expect("Failed to set_item on dict");
        dict.set_item::<PyObject, PyObject>("values".into_py(py), self.values.into_py(py))
            .expect("Failed to set_item on dict");
        dict.into_py(py)
    }
}

pub type IntOperator = Operator<u16>;
impl IntOperator {
    pub fn parser<'a, E: ParseError<&'a str>, F>(f: F) -> impl Parser<&'a str, IntOperator, E>
    where
        F: Parser<&'a str, (OperatorType, u16), E>,
    {
        map(f, |(operator, value)| {
            IntOperator::new(operator, vec![value])
        })
    }
}

pub struct IntOperatorBuilder;
impl IntOperatorBuilder {
    fn build<T>(operator: T, value: SingleOrPair<u16>) -> IntOperator
    where
        T: BuildOperatorType,
    {
        match value {
            SingleOrPair::Single(v) => IntOperator::new(operator.single(), vec![v]),
            SingleOrPair::Pair(f, s) => IntOperator::new(operator.range(), vec![f, s]),
        }
    }

    pub fn parser<'a, E: ParseError<&'a str>, F, T>(f: F) -> impl Parser<&'a str, IntOperator, E>
    where
        T: BuildOperatorType,
        F: Parser<&'a str, (T, SingleOrPair<u16>), E>,
    {
        map(f, |(operator, value)| {
            IntOperatorBuilder::build(operator, value)
        })
    }

    pub fn parser_many<'a, E: ParseError<&'a str>, F, T>(
        f: F,
    ) -> impl Parser<&'a str, Vec<IntOperator>, E>
    where
        T: BuildOperatorType + Clone,
        F: Parser<&'a str, (T, Vec<SingleOrPair<u16>>), E>,
    {
        map(f, |(operator, values)| {
            values
                .into_iter()
                .map(|i| IntOperatorBuilder::build(operator.clone(), i))
                .collect()
        })
    }

    pub fn parser_single<'a, E: ParseError<&'a str>, F, T>(f: F) -> impl Parser<&'a str, IntOperator, E>
    where
        T: BuildOperatorType,
        F: Parser<&'a str, (T, u16), E>,
    {
        map(f, |(operator, value)| {
            IntOperator::new(operator.single(), vec![value])
        })
    }

}

#[derive(Serialize)]
#[serde(transparent)]
pub struct DSCP(IntOperator);

impl DSCP {
    pub fn parser<'a, E: ParseError<&'a str>, F>(f: F) -> impl Parser<&'a str, DSCP, E>
    where
        F: Parser<&'a str, u16, E>,
    {
        map(f, |value| {
            DSCP(IntOperator::new(OperatorType::EQ, vec![value]))
        })
    }
}

impl IntoPy<PyObject> for DSCP {
    fn into_py(self, py: Python) -> PyObject {
        self.0.into_py(py)
    }
}

// // https://docs.rs/pyo3/0.15.2/pyo3/prelude/struct.Py.html#method.from_borrowed_ptr
// в чем разница между into_py и into как будто оба
// unsafe { PyObject::from_borrowed_ptr(py, self.as_ptr()) }
// py достается из самого объекта
// unsafe { Python::assume_gil_acquired()
// unsafe { Py::from_borrowed_ptr(obj.py(), obj.as_ptr()) }
//

pub type StringOperator<'a> = Operator<&'a str>;

pub enum SingleOrPair<T> {
    Single(T),
    Pair(T, T),
}
