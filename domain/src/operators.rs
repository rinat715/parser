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

pub trait RangeIntOperator {
    fn range(&self) -> OperatorType;
}

pub trait SingleIntOperator {
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

pub trait BuildIntOperator {
    fn operator(&mut self, operator: OperatorType);

    fn values(&mut self, values: Vec<u16>);
    
}

impl BuildIntOperator for IntOperator {
    fn operator(&mut self, operator: OperatorType) {
        self.operator = operator;
    }
    fn values(&mut self, values: Vec<u16>) {
        self.values.extend(values);
    }
}