// A local stand-in for the `uuid` crate: just enough of `Uuid` for the
// context-impl-app fixture, so the corpus builds offline. Keeping the type
// in its own crate keeps the pattern the fixture exercises true: the self
// type of the app's trait impls is foreign to the app. The value keeps the
// parsed text so a source flowing into `parse_str` stays visible to the
// data-flow engine, the way a real parse constructor would carry it.
use std::fmt;

#[derive(Debug)]
pub struct ParseError;

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid uuid")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uuid {
    value: String,
}

impl Uuid {
    pub fn parse_str(input: &str) -> Result<Uuid, ParseError> {
        let digits = input.chars().filter(|ch| ch.is_ascii_hexdigit()).count();
        if digits == 32 && input.chars().all(|ch| ch.is_ascii_hexdigit() || ch == '-') {
            Ok(Uuid {
                value: input.to_string(),
            })
        } else {
            Err(ParseError)
        }
    }

    pub fn as_u128(&self) -> u128 {
        self.value.len() as u128
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.value)
    }
}
