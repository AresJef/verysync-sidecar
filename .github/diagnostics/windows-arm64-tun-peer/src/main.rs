#[cfg(windows)]
mod windows;

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    windows::run()
}

#[cfg(not(windows))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("The TCP calibration peer requires the disposable Windows ARM64 runner".into())
}
