//! CI-only Rust unwind/drop probe. It never starts an official program.
use std::{cell::Cell, panic::AssertUnwindSafe};

struct DropFlag<'a>(&'a Cell<bool>);
impl Drop for DropFlag<'_> {
    fn drop(&mut self) {
        self.0.set(true);
    }
}

fn main() {
    let dropped = Cell::new(false);
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _guard = DropFlag(&dropped);
        panic!("synthetic standalone unwind probe");
    }));
    let caught = outcome.is_err();
    println!("unwind_caught={caught} drop_ran={}", dropped.get());
    if !caught || !dropped.get() {
        std::process::exit(23);
    }
}
