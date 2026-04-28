mod domain;
mod nftables;
mod parser;
mod test;

use domain::nftables::ACLRule;
use serde_derive::Serialize;

use pyo3::prelude::*;

#[macro_use]
extern crate log;

use nftables::rule;

#[pyclass]
#[derive(Serialize)]
pub struct Context {
    pub interfaces: Vec<String>,
    pub user_chains: Vec<String>,
}

#[pymethods]
impl Context {
    #[new]
    pub fn new(interfaces: Vec<String>, user_chains: Vec<String>) -> Self {
        Self {
            interfaces: interfaces,
            user_chains: user_chains,
        }
    }
}

#[pyfunction]
fn get<'a>(input: &'a str, context: &'a Context) -> PyResult<ACLRule<'a>> {
    let (_, rules) = rule(input, &context.user_chains, &context.interfaces).unwrap();

    Ok(rules)
}

/// A Python module implemented in Rust.
#[pymodule]
fn parser_rust(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get, m)?)?;
    m.add_class::<Context>()?;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyDict;
    use pyo3::Python;
    use pyo3::{IntoPy};
    
    #[test]
    fn test_parser_rust() {
        Python::with_gil(|py| {
            let interfaces = vec![String::from("swp1"), String::from("swp2")];
            let user_chains = vec![String::from("MY_CHAIN")];
            let context = Context::new(interfaces, user_chains);
            let res = get("-A INPUT -j DROP -i swp+ -o swp1", &context).unwrap();
            let obj = res.into_py(py);
            let dict:  &PyDict  = obj.extract(py).unwrap();
            assert_eq!(dict.len(), 3);
        });
    }
}

