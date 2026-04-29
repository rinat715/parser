use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyMapping, PyString};
use serde_derive::Serialize;

pub mod operators;
pub use operators::*;

pub mod ip;
pub use ip::*;

use macros::{is_not_null, ToPyDict};
pub mod nftables;

#[derive(Debug, PartialEq, Eq)]
pub struct ParseEnumError; // TODO нормальное название

pub fn is_empty<T>(values: &Vec<T>) -> bool {
    values.is_empty()
}

#[derive(Clone)]
pub enum StringOrU16<'a> {
    String(&'a str),
    Number(u16),
}

#[derive(Clone, Serialize)]
pub enum Protocol<'a> {
    #[serde(rename(serialize = "Protocol", deserialize = "Protocol"))]
    String(StringOperator<'a>),
    #[serde(rename(serialize = "Protocol", deserialize = "Protocol"))]
    Number(IntOperator),
}

impl<'a> Protocol<'a> {
    pub fn ip() -> Self {
        Self::String(StringOperator::new(OperatorType::EQ, vec!["ip"]))
    }
}

impl<'a> Protocol<'a> {
    // TODO ??????
    pub fn new(operator_type: OperatorType, value: StringOrU16<'a>) -> Self {
        match value {
            StringOrU16::Number(v) => Self::Number(IntOperator::new(operator_type, vec![v])),
            StringOrU16::String(v) => Self::String(StringOperator::new(operator_type, vec![v])),
        }
    }
}

impl<'a> IntoPy<PyObject> for Protocol<'a> {
    fn into_py(self, py: Python) -> PyObject {
        match self {
            Self::String(v) => v.into_py(py),
            Self::Number(v) => v.into_py(py),
        }
    }
}

#[derive(Serialize, Default, ToPyDict)]
#[serde(rename_all(serialize = "PascalCase", deserialize = "snake_case"))]
pub struct TCPUDPOptions<'a> {
    #[serde(skip_serializing_if = "is_empty")]
    source_ports: Vec<IntOperator>,
    #[serde(skip_serializing_if = "is_empty")]
    destination_ports: Vec<IntOperator>,
    #[serde(skip_serializing_if = "is_empty")]
    flags: Vec<StringOperator<'a>>,
}

impl<'a> TCPUDPOptions<'a> {
    pub fn new(
        source_ports: Vec<IntOperator>,
        destination_ports: Vec<IntOperator>,
        flags: Vec<StringOperator<'a>>,
    ) -> Self {
        Self {
            source_ports: source_ports,
            destination_ports: destination_ports,
            flags: flags,
        }
    }
}

pub static TCP_FLAGS_ALL: [&str; 6] = ["SYN", "ACK", "FIN", "RST", "URG", "PSH"];

pub fn tcp_flags<'a>(
    operator: OperatorType,
    value: (Vec<&'a str>, Vec<&'a str>),
) -> (StringOperator<'a>, StringOperator<'a>) {
    let values: Vec<&str>;

    if operator == OperatorType::EQ {
        values = value
            .0
            .into_iter()
            .filter(|x| !value.1.contains(x))
            .collect()
    } else {
        values = TCP_FLAGS_ALL
            .into_iter()
            .filter(|x| !value.0.contains(x))
            .collect()
    }

    let first = StringOperator::new(OperatorType::NEQ, values);
    let second: StringOperator<'_> = StringOperator::new(OperatorType::EQ, value.1);

    (first, second)
}

#[derive(Serialize, ToPyDict)]
pub struct IPv4Options {
    fragments: Vec<IntOperator>,
    dscp: Vec<IntOperator>,
    precedence: Vec<IntOperator>,
    ip_protocol_options: Vec<IntOperator>,
    ttl: Vec<IntOperator>,
    packet_length: Vec<IntOperator>,
}

impl IPv4Options {
    pub fn new(
        fragments: Vec<IntOperator>,
        dscp: Vec<IntOperator>,
        precedence: Vec<IntOperator>,
        ip_protocol_options: Vec<IntOperator>,
        ttl: Vec<IntOperator>,
        packet_length: Vec<IntOperator>,
    ) -> Self {
        Self {
            fragments: fragments,
            dscp: dscp,
            precedence: precedence,
            ip_protocol_options: ip_protocol_options,
            ttl: ttl,
            packet_length: packet_length,
        }
    }
}

#[derive(Serialize)]
pub enum IPOptions {
    #[serde(rename(serialize = "IPv4Options", deserialize = "IPv4Options"))]
    IPv4(IPv4Options),
}

impl IPOptions {
    pub fn new_ip4(
        fragments: Vec<IntOperator>,
        dscp: Vec<IntOperator>,
        precedence: Vec<IntOperator>,
        ip_protocol_options: Vec<IntOperator>,
        ttl: Vec<IntOperator>,
        packet_length: Vec<IntOperator>,
    ) -> Self {
        Self::IPv4(IPv4Options::new(
            fragments,
            dscp,
            precedence,
            ip_protocol_options,
            ttl,
            packet_length,
        ))
    }
}

impl IntoPy<PyObject> for IPOptions {
    fn into_py(self, py: Python) -> PyObject {
        match self {
            Self::IPv4(v) => v.into_py(py),
        }
    }
}

#[derive(Serialize, ToPyDict)]
pub struct ICMPOptions {
    code: Vec<IntOperator>,
    type_: Vec<IntOperator>,
}

#[derive(Serialize)]
pub struct ProtocolSetting<'a> {
    #[serde(flatten)]
    protocol: Option<Protocol<'a>>,
    #[serde(rename(serialize = "TCPUDPOptions", deserialize = "TCPUDPOptions"))]
    tcp_udp_options: Option<TCPUDPOptions<'a>>,
    #[serde(flatten)]
    ip_options: Option<IPOptions>,
    icmp_options: Option<ICMPOptions>,
}

impl<'a> ProtocolSetting<'a> {
    pub fn new(
        protocol: Option<Protocol<'a>>,
        tcp_udp_options: Option<TCPUDPOptions<'a>>,
        ip_options: Option<IPOptions>,
        icmp_options: Option<ICMPOptions>,
    ) -> Self {
        Self {
            protocol,
            tcp_udp_options,
            ip_options,
            icmp_options,
        }
    }

    #[is_not_null(all)]
    pub fn new_not_null(
        protocol: Option<Protocol<'a>>,
        tcp_udp_options: Option<TCPUDPOptions<'a>>,
        ip_options: Option<IPOptions>,
        icmp_options: Option<ICMPOptions>,
    ) -> Option<Self> {
        Some(Self::new(
            protocol,
            tcp_udp_options,
            ip_options,
            icmp_options,
        ))
    }
}

impl<'a> IntoPy<PyObject> for ProtocolSetting<'a> {
    fn into_py(self, py: Python) -> PyObject {
        
        let l = PyList::new(
            py,
            &[
                ("protocol", self.protocol.into_py(py)),
                ("tcp_udp_options", self.tcp_udp_options.into_py(py)),
                ("icmp_options", self.icmp_options.into_py(py)),
            ],
        );
        let res = PyDict::from_sequence(py, l.into()).unwrap();

        res.into_py(py) // Py_INCREF
    }
}

pub struct ProtocolSettingBuilder<'a> {
    //protocol
    protocol: Option<Protocol<'a>>,
    // tcp_udp_options
    source_ports: Vec<IntOperator>,
    destination_ports: Vec<IntOperator>,
    flags: Vec<StringOperator<'a>>,
    // IPv4Options
    fragments: Vec<IntOperator>,
    dscp: Vec<IntOperator>,
    precedence: Vec<IntOperator>,
    ip_protocol_options: Vec<IntOperator>,
    ttl: Vec<IntOperator>,
    packet_length: Vec<IntOperator>,
}

impl<'a> ProtocolSettingBuilder<'a> {
    pub fn new() -> Self {
        Self {
            protocol: None,
            source_ports: vec![],
            destination_ports: vec![],
            flags: vec![],
            fragments: vec![],
            dscp: vec![],
            precedence: vec![],
            ip_protocol_options: vec![],
            ttl: vec![],
            packet_length: vec![],
        }
    }

    #[is_not_null(all)]
    fn tcp_udp_options(
        sports: Vec<IntOperator>,
        dports: Vec<IntOperator>,
        flags: Vec<StringOperator<'a>>,
    ) -> Option<TCPUDPOptions<'a>> {
        Some(TCPUDPOptions::new(sports, dports, flags))
    }

    #[is_not_null(all)]
    fn ip_v_4options(
        fragments: Vec<IntOperator>,
        dscp: Vec<IntOperator>,
        precedence: Vec<IntOperator>,
        ip_protocol_options: Vec<IntOperator>,
        ttl: Vec<IntOperator>,
        packet_length: Vec<IntOperator>,
    ) -> Option<IPOptions> {
        Some(IPOptions::new_ip4(
            fragments,
            dscp,
            precedence,
            ip_protocol_options,
            ttl,
            packet_length,
        ))
    }

    pub fn set_protocol(&mut self, value: Protocol<'a>) {
        self.protocol = Some(value);
    }

    pub fn extend_ports(&mut self, values: Vec<IntOperator>) {
        self.source_ports.extend(values.clone());
        self.destination_ports.extend(values);
    }

    pub fn extend_source_ports(&mut self, values: Vec<IntOperator>) {
        self.source_ports.extend(values);
    }

    pub fn extend_destination_ports(&mut self, values: Vec<IntOperator>) {
        self.destination_ports.extend(values);
    }

    pub fn set_flags(&mut self, pair: (StringOperator<'a>, StringOperator<'a>)) {
        self.flags.push(pair.0);
        self.flags.push(pair.1);
    }

    pub fn add_ttl(&mut self, value: IntOperator) {
        self.ttl.push(value);
    }

    pub fn add_fragment(&mut self, value: IntOperator) {
        self.fragments.push(value);
    }

    pub fn add_dscp(&mut self, value: IntOperator) {
        self.dscp.push(value);
    }

    pub fn add_packet_length(&mut self, value: IntOperator) {
        self.packet_length.push(value);
    }

    pub fn extend_ip_protocol_options(&mut self, values: Vec<IntOperator>) {
        self.ip_protocol_options.extend(values);
    }

    pub fn build(self) -> Option<ProtocolSetting<'a>> {
        ProtocolSetting::new_not_null(
            self.protocol,
            Self::tcp_udp_options(self.source_ports, self.destination_ports, self.flags),
            Self::ip_v_4options(
                self.fragments,
                self.dscp,
                self.precedence,
                self.ip_protocol_options,
                self.ttl,
                self.packet_length,
            ),
            None,
        )
    }
}

#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all(serialize = "lowercase", deserialize = "UPPERCASE"))]
pub enum NormalizedAction {
    PERMIT,
    DENY,
    JUMP,
    PASS,
    RETURN,
}

impl<'a> IntoPy<PyObject> for NormalizedAction {
    fn into_py(self, py: Python) -> PyObject {
        let res = match self {
            Self::PERMIT => PyString::new(py, "PERMIT"),
            Self::DENY => PyString::new(py, "DENY"),
            Self::JUMP => PyString::new(py, "JUMP"),
            Self::PASS => PyString::new(py, "PASS"),
            Self::RETURN => PyString::new(py, "RETURN"),
        };
        res.into_py(py)
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub struct ActionSetting<'a, T> {
    action: T,
    option: &'a str,
}

impl<'a, T> ActionSetting<'a, T>
where
    T: TryInto<NormalizedAction, Error = ParseEnumError> + Clone + Default,
{
    pub fn new(action: T, option: &'a str) -> Self
    where
        T: TryInto<NormalizedAction>,
    {
        Self {
            action: action,
            option: option,
        }
    }

    pub fn normalized_action(&self) -> Result<NormalizedAction, ParseEnumError> {
        self.action.clone().try_into()
    }
}

impl<'a, T> IntoPy<PyObject> for ActionSetting<'a, T>
where
    T: IntoPy<PyObject>,
{
    fn into_py(self, py: Python) -> PyObject {
        let dict = PyDict::new(py);
        dict.set_item::<PyObject, PyObject>("operator".into_py(py), self.action.into_py(py))
            .expect("Failed to set_item on dict");
        dict.set_item::<PyObject, PyObject>("values".into_py(py), self.option.into_py(py))
            .expect("Failed to set_item on dict");
        dict.into_py(py)
    }
}

// бекпорт https://docs.rs/pyo3/latest/pyo3/types/trait.PyDictMethods.html#tymethod.update
pub fn dict_update(py: Python, first: &PyDict, second: &PyMapping) -> PyResult<()> {
    let result = unsafe { pyo3::ffi::PyDict_Update(first.into_ptr(), second.into_ptr()) };

    if result != -1 {
        Ok(())
    } else {
        Err(PyErr::fetch(py))
    }
}

#[derive(Serialize, Default)]
#[serde(rename_all(serialize = "PascalCase", deserialize = "snake_case"))]
pub struct ACL<'a, T> {
    action_modifiers: Vec<ActionSetting<'a, T>>,
    action: Vec<ActionSetting<'a, T>>,
    normalized_action: Option<NormalizedAction>,
    #[serde(skip_serializing_if = "is_empty")]
    interface_in: Vec<StringOperator<'a>>,
    #[serde(skip_serializing_if = "is_empty")]
    normalized_interface_in: Vec<&'a str>,
    #[serde(skip_serializing_if = "is_empty")]
    interface_out: Vec<StringOperator<'a>>,
    #[serde(skip_serializing_if = "is_empty")]
    normalized_interface_out: Vec<&'a str>,
    // zone_in: Vec<StringOperator<'a>>,
    // zone_out: Vec<StringOperator<'a>>,
}

impl<'a, T> ACL<'a, T>
where
    T: TryInto<NormalizedAction, Error = ParseEnumError> + Clone + Default,
{
    pub fn new(
        action: Vec<ActionSetting<'a, T>>,
        action_modifiers: Vec<ActionSetting<'a, T>>,
        normalized_action: Option<NormalizedAction>,
        interface_in: Vec<StringOperator<'a>>,
        normalized_interface_in: Vec<&'a str>,
        interface_out: Vec<StringOperator<'a>>,
        normalized_interface_out: Vec<&'a str>,
    ) -> Self {
        Self {
            action_modifiers,
            action,
            normalized_action,
            interface_in,
            normalized_interface_in,
            interface_out,
            normalized_interface_out,
        }
    }

    #[is_not_null(all)]
    pub fn new_not_null(
        action: Vec<ActionSetting<'a, T>>,
        action_modifiers: Vec<ActionSetting<'a, T>>,
        normalized_action: Option<NormalizedAction>,
        interface_in: Vec<StringOperator<'a>>,
        normalized_interface_in: Vec<&'a str>,
        interface_out: Vec<StringOperator<'a>>,
        normalized_interface_out: Vec<&'a str>,
    ) -> Option<Self> {
        Some(Self::new(
            action,
            action_modifiers,
            normalized_action,
            interface_in,
            normalized_interface_in,
            interface_out,
            normalized_interface_out,
        ))
    }

    pub fn extend_action_modifiers(&mut self, values: Vec<ActionSetting<'a, T>>) -> &mut Self {
        self.action_modifiers.extend(values);
        self
    }

    pub fn add_action(&mut self, value: ActionSetting<'a, T>) {
        self.normalized_action = value.normalized_action().ok();
        self.action.push(value);
    }

    pub fn add_action_modifier(&mut self, value: ActionSetting<'a, T>) {
        self.action_modifiers.push(value);
    }

    pub fn add_interface_in_vec(&mut self, values: Vec<StringOperator<'a>>) {
        self.normalized_interface_in = values.iter().map(|v| v.normalize()).collect();
        self.interface_in = values;
    }
    pub fn add_interface_out_vec(&mut self, values: Vec<StringOperator<'a>>) {
        self.normalized_interface_out = values.iter().map(|v| v.normalize()).collect();
        self.interface_out = values;
    }

    pub fn build(self) -> Option<Self> {
        Self::new_not_null(
            self.action,
            self.action_modifiers,
            self.normalized_action,
            self.interface_in,
            self.normalized_interface_in,
            self.interface_out,
            self.normalized_interface_out,
        )
    }
}

impl<'a, T> IntoPy<PyObject> for ACL<'a, T>
where
    T: IntoPy<PyObject>,
{
    fn into_py(self, py: Python) -> PyObject {
        let l = PyList::new(
            py,
            &[
                ("action_modifiers", self.action_modifiers.into_py(py)),
                ("action", self.action.into_py(py)),
                ("normalized_action", self.normalized_action.into_py(py)),
                ("interface_in", self.interface_in.into_py(py)),
                (
                    "normalized_interface_in",
                    self.normalized_interface_in.into_py(py),
                ),
                ("interface_out", self.interface_out.into_py(py)),
                (
                    "normalized_interface_out",
                    self.normalized_interface_out.into_py(py),
                ),
            ],
        );
        let res = PyDict::from_sequence(py, l.into()).unwrap();

        res.into_py(py) // Py_INCREF
    }
}

#[derive(Serialize, Default)]
#[serde(rename_all(serialize = "PascalCase", deserialize = "snake_case"))]
pub struct Rule<'a, T, T1> {
    line_number: Option<u16>,
    #[serde(flatten)]
    protocol: Option<ProtocolSetting<'a>>,
    source: Vec<EndpointSetting>,
    normalized_source: Vec<IPOperator>,
    destination: Vec<EndpointSetting>,
    normalized_destination: Vec<IPOperator>,
    #[serde(flatten)]
    extended: Option<T>,
    #[serde(flatten)]
    vendor_specific: Option<T1>,
}

impl<'a, T, T1> Rule<'a, T, T1>
where
    T: Default,
    T1: Default,
{
    pub fn new(
        line_number: Option<u16>,
        protocol: Option<ProtocolSetting<'a>>,
        source: Vec<EndpointSetting>,
        normalized_source: Vec<IPOperator>,
        destination: Vec<EndpointSetting>,
        normalized_destination: Vec<IPOperator>,
        extended: Option<T>,
        vendor_specific: Option<T1>,
    ) -> Self {
        Self {
            line_number,
            protocol,
            source,
            normalized_source,
            destination,
            normalized_destination,
            extended,
            vendor_specific,
        }
    }

    pub fn add_protocol(&mut self, value: ProtocolSetting<'a>) -> &mut Self {
        self.protocol = Some(value);
        self
    }

    pub fn add_source(&mut self, value: EndpointSetting) {
        self.normalized_source.push(value.normalize());
        self.source.push(value)
    }

    pub fn add_destination(&mut self, value: EndpointSetting) {
        self.normalized_destination.push(value.normalize());
        self.destination.push(value)
    }

    pub fn add_extended(&mut self, value: T) {
        self.extended = Some(value);
    }

    pub fn add_vendor(&mut self, value: T1) {
        self.vendor_specific = Some(value);
    }

    pub fn build(self) -> Self {
        Self::new(
            self.line_number,
            self.protocol,
            self.source,
            self.normalized_source,
            self.destination,
            self.normalized_destination,
            self.extended,
            self.vendor_specific,
        )
    }
}

impl<'a, T, T1> Merge for Rule<'a, T, T1> {
    fn merge(&mut self, value: Self) -> &mut Self {
        self.line_number
            .is_none()
            .then(|| self.line_number = value.line_number);
        self.protocol
            .is_none()
            .then(|| self.protocol = value.protocol);
        self.source.is_empty().then(|| self.source = value.source);
        self.normalized_source
            .is_empty()
            .then(|| self.normalized_source = value.normalized_source);
        self.destination
            .is_empty()
            .then(|| self.destination = value.destination);
        self.normalized_destination
            .is_empty()
            .then(|| self.normalized_destination = value.normalized_destination);
        self.extended
            .is_none()
            .then(|| self.extended = value.extended);
        self.vendor_specific
            .is_none()
            .then(|| self.vendor_specific = value.vendor_specific);
        self
    }
}

impl<'a, T, T1> IntoPy<PyObject> for Rule<'a, T, T1>
where
    T: IntoPy<PyObject>,
    T1: IntoPy<PyObject>,
{
    fn into_py(self, py: Python) -> PyObject {
        let l = PyList::new(py, &[("protocol", self.protocol.into_py(py))]);
        let res = PyDict::from_sequence(py, l.into()).unwrap();

        let extended_obj = self.extended.into_py(py);
        let extended_dict: &PyDict = extended_obj.extract(py).unwrap();

        dict_update(py, res, extended_dict.as_mapping()).unwrap();

        let vendor_obj = self.vendor_specific.into_py(py);
        let vendor_dict: &PyDict = vendor_obj.extract(py).unwrap();

        dict_update(py, res, vendor_dict.as_mapping()).unwrap();

        res.into_py(py) // Py_INCREF
    }
}

#[derive(Serialize, Clone)]
#[serde(rename_all(serialize = "PascalCase", deserialize = "snake_case"))]
pub struct EndpointSetting {
    address: IPOperator,
}

impl EndpointSetting {
    pub fn new(address: IPOperator) -> Self {
        Self { address }
    }

    pub fn normalize(&self) -> IPOperator {
        self.address.clone()
    }
}

pub trait Normalizator {
    type Arg;
    type Result;

    fn normalize(&self, value: &Self::Arg) -> Self::Result;
}

pub trait Merge {
    fn merge(&mut self, value: Self) -> &mut Self;
}


#[cfg(python_required)]
#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyDict;
    use pyo3::Python;
    use pyo3::{IntoPy};
    use pyo3::py_run;
    
    #[test]
    fn test_parser_rust() {
        Python::with_gil(|py| {
            let res = ProtocolSetting::new(Some(Protocol::ip()), None, None, None);

            let obj = res.into_py(py);
            let dict:  &PyDict  = obj.extract(py).unwrap();
            py_run!(py, dict, r#"
            assert str(dict) == "{'protocol': {'operator': 'EQ', 'values': ['ip']}, 'tcp_udp_options': None, 'icmp_options': None}"
            "#);
        });
    }
}
