//! Values that reach a sink only after going around a loop: each one is
//! assigned from a variable that the loop body only fills in later.

use std::net::TcpStream;
use std::process::Command;

pub fn run() {
    carried_by_for();
    carried_by_while();
    carried_by_loop();
    carried_through_nested_loops();
    carried_seventy_steps();
    carried_to_unmodeled_call();
    let input = std::env::var("LOOP_SUMMARY_INPUT").unwrap_or_default();
    let path = carried_to_return(input);
    let _ = std::fs::write(path, b"summary");
}

/// `current` is tainted from the second trip on, by the value `next` held
/// at the end of the first.
fn carried_by_for() {
    let mut current = String::new();
    let mut next = String::new();
    for _ in 0..3 {
        current = next.clone();
        next = std::env::var("FOR_INPUT").unwrap_or_default();
    }
    let _ = Command::new(current).status();
}

/// The same shape under `while`, whose condition is re-evaluated each trip.
fn carried_by_while() {
    let mut last = String::new();
    let mut pending = String::new();
    while last.len() < 64 {
        last = pending.clone();
        pending = std::env::var("WHILE_INPUT").unwrap_or_default();
    }
    let _ = std::fs::remove_file(last);
}

/// A sink inside a `loop` that only sees the value a previous trip stored.
fn carried_by_loop() {
    let mut previous = String::new();
    loop {
        if !previous.is_empty() {
            let _ = Command::new(&previous).status();
            break;
        }
        previous = std::env::var("LOOP_INPUT").unwrap_or_default();
    }
}

/// The inner loop reads what the outer loop stored on an earlier trip, which
/// it in turn copied from a source read on the trip before.
fn carried_through_nested_loops() {
    let mut inner = String::new();
    let mut outer = String::new();
    let mut staged = String::new();
    for _ in 0..3 {
        let mut step = 0;
        while step < 2 {
            inner = outer.clone();
            step += 1;
        }
        outer = staged.clone();
        staged = std::env::var("NESTED_INPUT").unwrap_or_default();
    }
    let _ = TcpStream::connect(inner);
}

/// Seventy links, each assigned from the next one: the source needs seventy
/// trips around the loop to reach `link_00`, more than the 64 passes the
/// compiler backend used to stop at.
fn carried_seventy_steps() {
    let mut link_00 = String::new();
    let mut link_01 = String::new();
    let mut link_02 = String::new();
    let mut link_03 = String::new();
    let mut link_04 = String::new();
    let mut link_05 = String::new();
    let mut link_06 = String::new();
    let mut link_07 = String::new();
    let mut link_08 = String::new();
    let mut link_09 = String::new();
    let mut link_10 = String::new();
    let mut link_11 = String::new();
    let mut link_12 = String::new();
    let mut link_13 = String::new();
    let mut link_14 = String::new();
    let mut link_15 = String::new();
    let mut link_16 = String::new();
    let mut link_17 = String::new();
    let mut link_18 = String::new();
    let mut link_19 = String::new();
    let mut link_20 = String::new();
    let mut link_21 = String::new();
    let mut link_22 = String::new();
    let mut link_23 = String::new();
    let mut link_24 = String::new();
    let mut link_25 = String::new();
    let mut link_26 = String::new();
    let mut link_27 = String::new();
    let mut link_28 = String::new();
    let mut link_29 = String::new();
    let mut link_30 = String::new();
    let mut link_31 = String::new();
    let mut link_32 = String::new();
    let mut link_33 = String::new();
    let mut link_34 = String::new();
    let mut link_35 = String::new();
    let mut link_36 = String::new();
    let mut link_37 = String::new();
    let mut link_38 = String::new();
    let mut link_39 = String::new();
    let mut link_40 = String::new();
    let mut link_41 = String::new();
    let mut link_42 = String::new();
    let mut link_43 = String::new();
    let mut link_44 = String::new();
    let mut link_45 = String::new();
    let mut link_46 = String::new();
    let mut link_47 = String::new();
    let mut link_48 = String::new();
    let mut link_49 = String::new();
    let mut link_50 = String::new();
    let mut link_51 = String::new();
    let mut link_52 = String::new();
    let mut link_53 = String::new();
    let mut link_54 = String::new();
    let mut link_55 = String::new();
    let mut link_56 = String::new();
    let mut link_57 = String::new();
    let mut link_58 = String::new();
    let mut link_59 = String::new();
    let mut link_60 = String::new();
    let mut link_61 = String::new();
    let mut link_62 = String::new();
    let mut link_63 = String::new();
    let mut link_64 = String::new();
    let mut link_65 = String::new();
    let mut link_66 = String::new();
    let mut link_67 = String::new();
    let mut link_68 = String::new();
    let mut link_69 = String::new();
    let mut link_70 = String::new();
    for _ in 0..3 {
        link_00 = link_01.clone();
        link_01 = link_02.clone();
        link_02 = link_03.clone();
        link_03 = link_04.clone();
        link_04 = link_05.clone();
        link_05 = link_06.clone();
        link_06 = link_07.clone();
        link_07 = link_08.clone();
        link_08 = link_09.clone();
        link_09 = link_10.clone();
        link_10 = link_11.clone();
        link_11 = link_12.clone();
        link_12 = link_13.clone();
        link_13 = link_14.clone();
        link_14 = link_15.clone();
        link_15 = link_16.clone();
        link_16 = link_17.clone();
        link_17 = link_18.clone();
        link_18 = link_19.clone();
        link_19 = link_20.clone();
        link_20 = link_21.clone();
        link_21 = link_22.clone();
        link_22 = link_23.clone();
        link_23 = link_24.clone();
        link_24 = link_25.clone();
        link_25 = link_26.clone();
        link_26 = link_27.clone();
        link_27 = link_28.clone();
        link_28 = link_29.clone();
        link_29 = link_30.clone();
        link_30 = link_31.clone();
        link_31 = link_32.clone();
        link_32 = link_33.clone();
        link_33 = link_34.clone();
        link_34 = link_35.clone();
        link_35 = link_36.clone();
        link_36 = link_37.clone();
        link_37 = link_38.clone();
        link_38 = link_39.clone();
        link_39 = link_40.clone();
        link_40 = link_41.clone();
        link_41 = link_42.clone();
        link_42 = link_43.clone();
        link_43 = link_44.clone();
        link_44 = link_45.clone();
        link_45 = link_46.clone();
        link_46 = link_47.clone();
        link_47 = link_48.clone();
        link_48 = link_49.clone();
        link_49 = link_50.clone();
        link_50 = link_51.clone();
        link_51 = link_52.clone();
        link_52 = link_53.clone();
        link_53 = link_54.clone();
        link_54 = link_55.clone();
        link_55 = link_56.clone();
        link_56 = link_57.clone();
        link_57 = link_58.clone();
        link_58 = link_59.clone();
        link_59 = link_60.clone();
        link_60 = link_61.clone();
        link_61 = link_62.clone();
        link_62 = link_63.clone();
        link_63 = link_64.clone();
        link_64 = link_65.clone();
        link_65 = link_66.clone();
        link_66 = link_67.clone();
        link_67 = link_68.clone();
        link_68 = link_69.clone();
        link_69 = link_70.clone();
        link_70 = std::env::var("SEVENTY_INPUT").unwrap_or_default();
    }
    let _ = Command::new(link_00).status();
}

/// A call nothing models, reached only by a value carried around the loop.
/// The report says taint may be lost there, once for its one call site,
/// counting from the fixpoint rather than from a trip that had not yet seen
/// the value.
fn carried_to_unmodeled_call() {
    let mut current = String::new();
    let mut next = String::new();
    for _ in 0..3 {
        let _seen = std::hint::black_box(current.clone());
        current = next.clone();
        next = std::env::var("UNMODELED_INPUT").unwrap_or_default();
    }
}

/// The parameter reaches the return value only through a loop-carried copy,
/// so the summary callers rely on must see through the loop too.
fn carried_to_return(value: String) -> String {
    let mut result = String::new();
    let mut held = String::new();
    for _ in 0..2 {
        result = held.clone();
        held = value.clone();
    }
    result
}
