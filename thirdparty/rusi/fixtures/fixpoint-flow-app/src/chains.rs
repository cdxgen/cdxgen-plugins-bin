//! Call chains twelve functions deep, written callers first: the order in
//! which a round-by-round summary pass learns one level per round.

use std::io::Write;
use std::net::TcpStream;
use std::process::Command;

pub fn run() {
    sink_chain();
    fetch_chain();
    pass_chain();
}

/// An environment value handed down twelve calls to a process spawn.
fn sink_chain() {
    let input = std::env::var("SINK_CHAIN_INPUT").unwrap_or_default();
    sink_01(input);
}

/// A source read twelve calls down and returned all the way up.
fn fetch_chain() {
    let path = fetch_01();
    let _ = std::fs::write(path, b"report");
}

/// An environment value passed through twelve calls and back.
fn pass_chain() {
    let input = std::env::var("PASS_CHAIN_INPUT").unwrap_or_default();
    let address = pass_01(input);
    if let Ok(mut stream) = TcpStream::connect(address) {
        let _ = stream.write_all(b"ping");
    }
}

fn sink_01(value: String) {
    sink_02(value);
}

fn sink_02(value: String) {
    sink_03(value);
}

fn sink_03(value: String) {
    sink_04(value);
}

fn sink_04(value: String) {
    sink_05(value);
}

fn sink_05(value: String) {
    sink_06(value);
}

fn sink_06(value: String) {
    sink_07(value);
}

fn sink_07(value: String) {
    sink_08(value);
}

fn sink_08(value: String) {
    sink_09(value);
}

fn sink_09(value: String) {
    sink_10(value);
}

fn sink_10(value: String) {
    sink_11(value);
}

fn sink_11(value: String) {
    sink_12(value);
}

fn sink_12(value: String) {
    let _ = Command::new(value).status();
}

fn fetch_01() -> String {
    fetch_02()
}

fn fetch_02() -> String {
    fetch_03()
}

fn fetch_03() -> String {
    fetch_04()
}

fn fetch_04() -> String {
    fetch_05()
}

fn fetch_05() -> String {
    fetch_06()
}

fn fetch_06() -> String {
    fetch_07()
}

fn fetch_07() -> String {
    fetch_08()
}

fn fetch_08() -> String {
    fetch_09()
}

fn fetch_09() -> String {
    fetch_10()
}

fn fetch_10() -> String {
    fetch_11()
}

fn fetch_11() -> String {
    fetch_12()
}

fn fetch_12() -> String {
    std::env::var("FETCH_CHAIN_INPUT").unwrap_or_default()
}

fn pass_01(value: String) -> String {
    pass_02(value)
}

fn pass_02(value: String) -> String {
    pass_03(value)
}

fn pass_03(value: String) -> String {
    pass_04(value)
}

fn pass_04(value: String) -> String {
    pass_05(value)
}

fn pass_05(value: String) -> String {
    pass_06(value)
}

fn pass_06(value: String) -> String {
    pass_07(value)
}

fn pass_07(value: String) -> String {
    pass_08(value)
}

fn pass_08(value: String) -> String {
    pass_09(value)
}

fn pass_09(value: String) -> String {
    pass_10(value)
}

fn pass_10(value: String) -> String {
    pass_11(value)
}

fn pass_11(value: String) -> String {
    pass_12(value)
}

fn pass_12(value: String) -> String {
    value
}
