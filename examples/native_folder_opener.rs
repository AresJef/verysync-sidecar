//! Short-lived engine-test opener capture. Never opens a desktop application.
use std::{env, fs::OpenOptions, io::Write, path::PathBuf};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(
        env::var_os("VERYSYNC_TEST_OPENER_CAPTURE_DIR")
            .ok_or("explicit owned capture directory required")?,
    );
    if !root.is_absolute() || !root.is_dir() {
        return Err("owned absolute capture directory required".into());
    }
    let arguments = env::args_os()
        .skip(1)
        .map(|v| v.into_string().map_err(|_| "non UTF-8 fixture argument"))
        .collect::<Result<Vec<_>, _>>()?;
    if arguments.is_empty() || arguments.len() > 16 || arguments.iter().any(|a| a.len() > 16384) {
        return Err("bounded explicit opener arguments required".into());
    }
    let path = root.join(format!("{}.argv", std::process::id()));
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    for argument in arguments {
        file.write_all(argument.as_bytes())?;
        file.write_all(&[0])?;
    }
    file.sync_all()?;
    Ok(())
}
