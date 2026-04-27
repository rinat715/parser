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
