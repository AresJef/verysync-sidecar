//! Explicit CI probe for the pinned interpreter's argv convention.
fn main() {
    let arguments: Vec<_> = std::env::args_os().collect();
    let matches = |index: usize, expected: &str| {
        arguments
            .get(index)
            .is_some_and(|argument| argument == expected)
    };
    let arg0 = arguments
        .first()
        .and_then(|value| std::path::Path::new(value).file_name())
        .is_some_and(|name| name == "qemu-argv-probe");
    let canary = matches(1, "argv-canary");
    let threads = matches(2, "--test-threads=1");
    let capture = matches(3, "--nocapture");
    println!(
        "argc={} arg0_match={arg0} canary_match={canary} threads_match={threads} capture_match={capture}",
        arguments.len()
    );
    if arguments.len() != 4 || !arg0 || !canary || !threads || !capture {
        std::process::exit(23);
    }
}
