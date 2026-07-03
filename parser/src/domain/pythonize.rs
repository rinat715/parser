use pyo3::prelude::*;
use pyo3::types::{IntoPyDict, PyDict, PyList, PyMapping, PyString};

pub trait ToPyString {
    fn to_py_str(self, py: Python<'_>) -> &'_ PyString
    where
        Self: Sized;
}

pub fn insert<T: IntoPy<PyObject>>(py: Python, dict: &PyDict, key: &str, value: T) {
    let _ = dict.set_item(key, value.into_py(py)); // TODO залогировать ошибку 
    // откуда вoзьмeтcя TypeError
}

pub fn try_insert<T: IntoPy<PyObject>>(py: Python, dict: &PyDict, key: &str, value: Option<T>) {
    if let Some(v) = value {
        let _ = dict.set_item(key, v.into_py(py)); // TODO залогировать ошибку 
        // откуда возьмется TypeError
    }
}

pub fn tuple<T: IntoPy<PyObject>>(
    py: Python,
    key: &'static str,
    value: T,
) -> (&'static str, PyObject) {
    (key, value.into_py(py))
}

// бекпорт https://docs.rs/pyo3/latest/pyo3/types/trait.PyDictMethods.html#tymethod.update
pub fn dict_update(first: &PyDict, second: &PyMapping) {
    let result = unsafe { pyo3::ffi::PyDict_Update(first.into_ptr(), second.into_ptr()) };

    if result != -1 {
    } else {
        // TODO логировать ошибку
        //Err(PyErr::fetch(py))
    }
}

impl IntoPy<PyObject> for crate::domain::IPProtocolOptions {
    fn into_py(self, py: Python) -> PyObject {
        match self {
            Self::ANY => Self::ANY_OPERATOR.into_py(py),
            Self::LooseSourceRouting => Self::LOOSE_SOURCE_ROUTING_OPERATOR.into_py(py),
            Self::NoRecordRoute => Self::NO_RECORD_ROUTE_OPERATOR.into_py(py),
            Self::NoRouterAlert => Self::NO_ROUTER_ALERT_OPERATOR.into_py(py),
            Self::NoSourceRouting => Self::NO_SOURCE_ROUTING_OPERATOR.into_py(py),
            Self::NoTimestamp => Self::NO_TIMESTAMP_OPERATOR.into_py(py),
            Self::RecordRoute => Self::RECORD_ROUTE_OPERATOR.into_py(py),
            Self::RouterAlert => Self::ROUTER_ALERT_OPERATOR.into_py(py),
            Self::StrictSourceRouting => Self::STRICT_SOURCE_ROUTING_OPERATOR.into_py(py),
            Self::Timestamp => Self::TIMESTAMP_OPERATOR.into_py(py),
        }
    }
}

impl IntoPy<PyObject> for crate::domain::ProtocolSetting {
    fn into_py(self, py: Python) -> PyObject {
        let res = match self.0 {
            crate::domain::Protocol::TCP(v) => v.into_py_dict(py),
            crate::domain::Protocol::UDP(v) => v.into_py_dict(py),
            crate::domain::Protocol::String(v) => v.into_py_dict(py),
            crate::domain::Protocol::Number(v) => v.into_py_dict(py),
        };

        if let Some(v) = self.1 {
            insert(py, res, "IPv4Options", v);
        }

        res.into_py(py) // Py_INCREF
    }
}

impl<U, T1> IntoPy<PyObject> for crate::domain::ACLRule<crate::domain::ACL<U>, T1>
where
    U: IntoPy<PyObject>,
    T1: IntoPyDict,
{
    fn into_py(self, py: Python) -> PyObject {
        let base = self.0.into_py_dict(py);
        let extended_dict = self.1.into_py_dict(py);
        let vendor_dict = self.2.into_py_dict(py);

        dict_update(base, extended_dict.as_mapping());
        dict_update(base, vendor_dict.as_mapping());

        base.into_py(py) // Py_INCREF
    }
}

impl<'a> IntoPy<PyObject> for crate::domain::EndpointSetting {
    fn into_py(self, py: Python) -> PyObject {
        let l = match self {
            Self::IPOperator(v) => PyList::new(py, &[tuple(py, "Address", v)]),
        };

        let dict = PyDict::from_sequence(py, l.into()).unwrap_or(PyDict::new(py));

        dict.into_py(py) // Py_INCREF
    }
}

impl<T> IntoPy<PyObject> for crate::domain::generic::Tuple<T>
where
    T: IntoPy<PyObject>,
{
    fn into_py(self, py: Python) -> PyObject {
        match self {
            Self::Single(v) => (v,).into_py(py),
            Self::Pair(f, s) => (f, s).into_py(py),
        }
    }
}

impl IntoPy<PyObject> for crate::domain::generic::Str {
    fn into_py(self, py: Python) -> PyObject {
        self.as_str().into_py(py)
    }
}
