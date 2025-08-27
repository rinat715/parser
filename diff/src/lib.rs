use termdiff::{DrawDiff};
use std::borrow::Cow;
use termdiff::Theme;
use std::fmt::{Display, Formatter};
 use colored::Colorize;

#[derive(Default, Copy, Clone, Debug)]
pub struct CustomSignsTheme {}

impl Theme for CustomSignsTheme {
    fn equal_prefix<'this>(&self) -> Cow<'this, str> {
        "".into()
    }

    fn delete_prefix<'this>(&self) -> Cow<'this, str> {
        "-".into()
    }

    fn insert_prefix<'this>(&self) -> Cow<'this, str> {
        "+".into()
    }

    fn header<'this>(&self) -> Cow<'this, str> {
        "".into()
    }
    
}

pub struct Diff<'a> {
    file_name: &'a str,
    name: &'a str,
    actual: &'a str,
    excepted: &'a str,
}

impl<'a> Diff<'a> {
    pub fn new(file_name: &'a str, name: &'a str, actual: &'a str, excepted: &'a str) -> Self {
        Self {
            file_name: file_name,
            name: name,
            actual: actual,
            excepted: excepted,
        }
    }
}

impl Display for Diff<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\n\nFile: {}", self.file_name.red())?;

        writeln!(f, "Test case: {}\n", self.name)?;

        writeln!(f, "{}", "ACTUAL:\n".green())?;

        writeln!(f, "{}", self.actual)?;

        writeln!(f, "{}", "EXPECTED:\n".green())?;

        writeln!(f, "{}", self.excepted)?;

        writeln!(f, "{}", "DIFF:".red())?;

        let theme = CustomSignsTheme::default();
        let diff = format!("{}", DrawDiff::new(self.actual, self.excepted, &theme));
        
        write!(f, "{}", diff)?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // !TODO
}
