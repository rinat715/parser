mod domain;
mod nftables;
mod parser;
mod test;

use serde_derive::Serialize;

use pyo3::prelude::*;

#[macro_use]
extern crate log;

use std::cell::RefCell;
use std::rc::Rc;

use crate::domain::nftables::Table;

#[pyclass]
#[derive(Serialize, Clone)]
pub struct Context {
    pub interfaces: Vec<String>,       // TODO tp_traverse?
    pub user_chain_names: Vec<String>, // TODO tp_traverse?
}

#[pymethods]
impl Context {
    #[new]
    pub fn new(interfaces: Vec<String>, user_chain_names: Vec<String>) -> Self {
        Self {
            interfaces,
            user_chain_names,
        }
    }

    fn set(&mut self, user_chain_names: Vec<String>) {
        self.user_chain_names = user_chain_names
    }
}

#[pyfunction]
fn get<'a>(input: &'a str, context: &'a Context) -> PyResult<Vec<Table>> {
    let ctx: Rc<RefCell<_>> = Rc::new(RefCell::new(context.clone()));
    let (_, rules) = nftables::tables(&ctx)(input).unwrap();

    Ok(rules)
}

/// A Python module implemented in Rust.
#[pymodule]
fn parser_rust(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get, m)?)?;
    m.add_class::<Context>()?;
    Ok(())
}
