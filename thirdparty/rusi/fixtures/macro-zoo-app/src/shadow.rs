//! A definition shadowed by a later one of the same name: the first call
//! uses the first definition, the second call the second.

#[allow(unused_macros)]
macro_rules! pick {
    () => {
        String::from("first")
    };
}

pub fn first() -> String {
    pick!()
}

macro_rules! pick {
    () => {
        std::env::var("MACRO_ZOO_PICK").unwrap_or_default()
    };
}

pub fn second() -> String {
    pick!()
}
