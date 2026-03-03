mod nftables;
mod b4tech;
mod test;
use pyo3::prelude::*;
use pyo3::Python;
use domain::nftables::ActionType;

#[macro_use]
extern crate log;


use nftables::rule;

#[pyfunction]
fn get<'a>(input: &'a str, user_chains: Vec<&'a str>) -> PyResult<domain::nftables::ACLRule<'a, ActionType>> {
    let borrow = user_chains;
    let (_, rules) = rule(input, &borrow).unwrap();
    Ok(rules)
    
}

/// A Python module implemented in Rust.
#[pymodule]
fn parser_rust(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get, m)?)?;
    Ok(())
}

