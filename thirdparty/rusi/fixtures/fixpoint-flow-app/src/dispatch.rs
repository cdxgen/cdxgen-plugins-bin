//! A trait object with forty implementations, more than the 32 candidate
//! targets the compiler backend used to keep for one call. Every
//! implementation hands its input to a process spawn, so each one the
//! dispatch reaches is one more slice.

use std::process::Command;

trait Stage {
    fn apply(&self, input: String) -> String;
}

pub fn run() {
    let stages: Vec<Box<dyn Stage>> = vec![
        Box::new(Stage01),
        Box::new(Stage02),
        Box::new(Stage03),
        Box::new(Stage04),
        Box::new(Stage05),
        Box::new(Stage06),
        Box::new(Stage07),
        Box::new(Stage08),
        Box::new(Stage09),
        Box::new(Stage10),
        Box::new(Stage11),
        Box::new(Stage12),
        Box::new(Stage13),
        Box::new(Stage14),
        Box::new(Stage15),
        Box::new(Stage16),
        Box::new(Stage17),
        Box::new(Stage18),
        Box::new(Stage19),
        Box::new(Stage20),
        Box::new(Stage21),
        Box::new(Stage22),
        Box::new(Stage23),
        Box::new(Stage24),
        Box::new(Stage25),
        Box::new(Stage26),
        Box::new(Stage27),
        Box::new(Stage28),
        Box::new(Stage29),
        Box::new(Stage30),
        Box::new(Stage31),
        Box::new(Stage32),
        Box::new(Stage33),
        Box::new(Stage34),
        Box::new(Stage35),
        Box::new(Stage36),
        Box::new(Stage37),
        Box::new(Stage38),
        Box::new(Stage39),
        Box::new(Stage40),
    ];
    let input = std::env::var("STAGE_INPUT").unwrap_or_default();
    for stage in &stages {
        let _ = stage.apply(input.clone());
    }
}

/// An inherent method, on a type whose name holds the letters of " as ".
/// Rust resolves the call statically, so both backends follow it to the
/// spawn through the call's own target; an inherent method is never a
/// candidate of a trait-object call.
struct Database;

impl Database {
    fn perform(&self, statement: String) {
        let _ = Command::new(statement).status();
    }
}

pub fn run_inherent() {
    let statement = std::env::var("DATABASE_INPUT").unwrap_or_default();
    Database.perform(statement);
}

struct Stage01;

impl Stage for Stage01 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-01").status();
        input
    }
}

struct Stage02;

impl Stage for Stage02 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-02").status();
        input
    }
}

struct Stage03;

impl Stage for Stage03 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-03").status();
        input
    }
}

struct Stage04;

impl Stage for Stage04 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-04").status();
        input
    }
}

struct Stage05;

impl Stage for Stage05 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-05").status();
        input
    }
}

struct Stage06;

impl Stage for Stage06 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-06").status();
        input
    }
}

struct Stage07;

impl Stage for Stage07 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-07").status();
        input
    }
}

struct Stage08;

impl Stage for Stage08 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-08").status();
        input
    }
}

struct Stage09;

impl Stage for Stage09 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-09").status();
        input
    }
}

struct Stage10;

impl Stage for Stage10 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-10").status();
        input
    }
}

struct Stage11;

impl Stage for Stage11 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-11").status();
        input
    }
}

struct Stage12;

impl Stage for Stage12 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-12").status();
        input
    }
}

struct Stage13;

impl Stage for Stage13 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-13").status();
        input
    }
}

struct Stage14;

impl Stage for Stage14 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-14").status();
        input
    }
}

struct Stage15;

impl Stage for Stage15 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-15").status();
        input
    }
}

struct Stage16;

impl Stage for Stage16 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-16").status();
        input
    }
}

struct Stage17;

impl Stage for Stage17 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-17").status();
        input
    }
}

struct Stage18;

impl Stage for Stage18 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-18").status();
        input
    }
}

struct Stage19;

impl Stage for Stage19 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-19").status();
        input
    }
}

struct Stage20;

impl Stage for Stage20 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-20").status();
        input
    }
}

struct Stage21;

impl Stage for Stage21 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-21").status();
        input
    }
}

struct Stage22;

impl Stage for Stage22 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-22").status();
        input
    }
}

struct Stage23;

impl Stage for Stage23 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-23").status();
        input
    }
}

struct Stage24;

impl Stage for Stage24 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-24").status();
        input
    }
}

struct Stage25;

impl Stage for Stage25 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-25").status();
        input
    }
}

struct Stage26;

impl Stage for Stage26 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-26").status();
        input
    }
}

struct Stage27;

impl Stage for Stage27 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-27").status();
        input
    }
}

struct Stage28;

impl Stage for Stage28 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-28").status();
        input
    }
}

struct Stage29;

impl Stage for Stage29 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-29").status();
        input
    }
}

struct Stage30;

impl Stage for Stage30 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-30").status();
        input
    }
}

struct Stage31;

impl Stage for Stage31 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-31").status();
        input
    }
}

struct Stage32;

impl Stage for Stage32 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-32").status();
        input
    }
}

struct Stage33;

impl Stage for Stage33 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-33").status();
        input
    }
}

struct Stage34;

impl Stage for Stage34 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-34").status();
        input
    }
}

struct Stage35;

impl Stage for Stage35 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-35").status();
        input
    }
}

struct Stage36;

impl Stage for Stage36 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-36").status();
        input
    }
}

struct Stage37;

impl Stage for Stage37 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-37").status();
        input
    }
}

struct Stage38;

impl Stage for Stage38 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-38").status();
        input
    }
}

struct Stage39;

impl Stage for Stage39 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-39").status();
        input
    }
}

struct Stage40;

impl Stage for Stage40 {
    fn apply(&self, input: String) -> String {
        let _ = Command::new(&input).arg("--stage-40").status();
        input
    }
}
