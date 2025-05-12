use serde_derive::Deserialize;
use std::env;
use std::env::VarError;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use toml::Value;

#[derive(Deserialize)]
pub struct TestSuit {
    pub input: String,
    pub remaining: String,
    pub expected: Value,
}

#[derive(Deserialize)]
pub struct TestSuitStr {
    pub input: String,
    pub remaining: String,
    pub expected: String,
}

pub fn fixture_dir() -> Result<PathBuf, VarError> {
    let path = PathBuf::new();
    let manifest = env::var("CARGO_MANIFEST_DIR")?;

    Ok(path.join(manifest).join("fixtures"))
}

pub fn read_file_to_string(path: &str, buf: &mut String) {
    let mut f = File::open(path).unwrap();
    f.read_to_string(buf).unwrap();
}