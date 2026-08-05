use pyo3::prelude::*;

#[macro_use]
extern crate log;

use std::cell::RefCell;
use std::rc::Rc;

#[pyfunction]
fn get<'a>(input: &'a str, context: &'a parser_lib::Context) -> PyResult<Vec<parser_lib::Table>> {
    let ctx: Rc<RefCell<_>> = Rc::new(RefCell::new(context.clone()));
    let (_, rules) = parser_lib::parser(&ctx)(input).unwrap();

    Ok(rules)
}

/// A Python module implemented in Rust.
#[pymodule]
fn parser_rust(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get, m)?)?;
    m.add_class::<parser_lib::Context>()?;
    Ok(())
}
