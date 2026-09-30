//! Taint through recursion: a self-recursive countdown, a mutually
//! recursive pair, and a recursive walk down a linked structure.

use std::net::TcpStream;
use std::process::Command;

pub fn run() {
    let input = std::env::var("COUNTDOWN_INPUT").unwrap_or_default();
    countdown(input, 3);

    let input = std::env::var("PARITY_INPUT").unwrap_or_default();
    let _ = is_even(input, 4);

    let input = std::env::var("CHAIN_NODE_INPUT").unwrap_or_default();
    let list = Node {
        value: String::from("head"),
        next: Some(Box::new(Node {
            value: input,
            next: None,
        })),
    };
    let tail = last_value(&list);
    let _ = TcpStream::connect(tail);
}

fn countdown(value: String, remaining: u32) {
    if remaining == 0 {
        let _ = Command::new(value).status();
    } else {
        countdown(value, remaining - 1);
    }
}

fn is_even(value: String, remaining: u32) -> bool {
    if remaining == 0 {
        true
    } else {
        is_odd(value, remaining - 1)
    }
}

fn is_odd(value: String, remaining: u32) -> bool {
    if remaining == 0 {
        let _ = std::fs::remove_file(value);
        false
    } else {
        is_even(value, remaining - 1)
    }
}

struct Node {
    value: String,
    next: Option<Box<Node>>,
}

/// Recurses on a field of its own parameter, so the fields it can return
/// sit ever deeper under that parameter.
fn last_value(node: &Node) -> String {
    match &node.next {
        Some(next) => last_value(next),
        None => node.value.clone(),
    }
}
