//! Flows that only a fixpoint iterated to convergence finds: call chains
//! deeper than any fixed number of rounds, recursion, values carried from
//! one trip around a loop to the next, a trait object with more
//! implementations than a fixed candidate limit, and an inherent method
//! that no trait-object call may reach.

mod chains;
mod dispatch;
mod loops;
mod recursion;

fn main() {
    chains::run();
    loops::run();
    recursion::run();
    dispatch::run();
    dispatch::run_inherent();
}
