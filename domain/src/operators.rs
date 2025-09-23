use serde_derive::Serialize;

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

impl BuildOperatorType for OperatorType {
    fn range(&self) -> OperatorType {
        match self {
            Self::RANGE => Self::RANGE,
            Self::NotRange => Self::NotRange,

            _ => panic!("Not convert to range"),
        }
    }

    fn single(&self) -> OperatorType {
        match self {
            Self::EQ => Self::EQ,
            Self::NEQ => Self::NEQ,
            Self::GT => Self::GT,
            Self::LT => Self::LT,

            _ => panic!("Not convert to single"),
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

pub type IntOperator = Operator<u16>;
impl IntOperator {
    pub fn build<T>(operator: T, value: SingleOrPair<u16>) -> IntOperator
    where
        T: BuildOperatorType,
    {
        match value {
            SingleOrPair::Single(v) => IntOperator::new(operator.single(), vec![v]),
            SingleOrPair::Pair(f, s) => IntOperator::new(operator.range(), vec![f, s]),
        }
    }
}

pub type StringOperator<'a> = Operator<&'a str>;

pub enum SingleOrPair<T> {
    Single(T),
    Pair(T, T),
}
