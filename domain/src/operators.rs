use serde_derive::Serialize;


#[derive(Serialize, Clone, PartialEq)]
pub enum OperatorType {
    EQ,
    NEQ,
    RANGE,
    NotRange
}


#[derive(Serialize)]
pub struct StringOperator<'a> {
    operator: OperatorType,
    values: Vec<&'a str>
}

impl<'a> StringOperator<'a> {
    pub fn new(operator_type: OperatorType, values: Vec<&'a str>) -> Self {
        Self { operator: operator_type, values: values }
    }
}

pub trait BuildIntOperator {
    fn range(&self) -> OperatorType;

    fn single(&self) -> OperatorType;
}


#[derive(Serialize, Clone)]
pub struct IntOperator {
    operator: OperatorType,
    values: Vec<u16>
}

impl IntOperator {
    pub fn new(operator_type: OperatorType, values: Vec<u16>) -> Self {
        Self { operator: operator_type, values: values }
    }
}