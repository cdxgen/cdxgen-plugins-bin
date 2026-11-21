//! An impl-generating macro: one unit type per `ident` in a repetition,
//! each with an env to process-exec flow and a serializer.

macro_rules! make_units {
    ( $( $t:ident ),* ) => {
        $(
            pub struct $t(pub u32);

            impl $t {
                pub fn danger(&self) -> std::process::Output {
                    std::process::Command::new("sh")
                        .arg("-c")
                        .arg(std::env::var("MACRO_ZOO_ZONE").unwrap())
                        .output()
                        .unwrap()
                }

                pub fn to_json(&self) -> String {
                    $crate::helper::enc(self.0)
                }
            }
        )*
    };
}

pub(crate) use make_units;
