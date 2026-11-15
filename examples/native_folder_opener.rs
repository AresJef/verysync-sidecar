//! Short-lived engine-test opener capture. Never opens a desktop application.
use std::{
    env,
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    time::{Duration, Instant},
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(
        env::var_os("VERYSYNC_TEST_OPENER_CAPTURE_DIR")
            .ok_or("explicit owned capture directory required")?,
    );
    if !root.is_absolute() || !root.is_dir() {
        return Err("owned absolute capture directory required".into());
    }
    if env::var("VERYSYNC_TEST_BROWSER_HOLD").as_deref() == Ok("1")
        && env::var("VERYSYNC_TEST_BROWSER_ACTOR").as_deref() != Ok("1")
    {
        // Model the OS opener: dispatch one actor, then return. The actor alone
        // records argv and waits for an explicit stop from the test.
        let mut child = std::process::Command::new(env::current_exe()?)
            .args(env::args_os().skip(1))
            .env("VERYSYNC_TEST_BROWSER_ACTOR", "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let journal = root.join(format!("{}.owned", child.id()));
        let recorded = (|| -> std::io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(journal)?;
            file.write_all(b"exact actor PID returned by spawn")?;
            file.sync_all()
        })();
        if let Err(error) = recorded {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error.into());
        }
        return Ok(());
    }
    let arguments = env::args_os()
        .skip(1)
        .map(|v| v.into_string().map_err(|_| "non UTF-8 fixture argument"))
        .collect::<Result<Vec<_>, _>>()?;
    if arguments.is_empty() || arguments.len() > 16 || arguments.iter().any(|a| a.len() > 16384) {
        return Err("bounded explicit opener arguments required".into());
    }
    let path = root.join(format!("{}.argv", std::process::id()));
    if path.try_exists()? {
        return Err("owned capture PID already recorded".into());
    }
    let partial = path.with_extension("argv-partial");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)?;
    for argument in arguments {
        file.write_all(argument.as_bytes())?;
        file.write_all(&[0])?;
    }
    file.sync_all()?;
    drop(file);
    std::fs::rename(partial, path)?;
    // Opt-in browser fixture only. The native launcher returns before this
    // actor observes a marker written by the caller after receiving its result.
    if env::var("VERYSYNC_TEST_BROWSER_HOLD").as_deref() == Ok("1") {
        let pid = std::process::id();
        let deadline = Instant::now() + Duration::from_secs(30);
        while !root.join(format!("{pid}.stop")).exists() {
            if Instant::now() >= deadline {
                return Err("owned browser fixture exceeded its lifetime bound".into());
            }
            if root.join(format!("{pid}.after-root")).exists() {
                std::fs::write(
                    root.join(format!("{pid}.alive")),
                    b"executed after root result",
                )?;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        std::fs::write(
            root.join(format!("{pid}.finished")),
            b"explicit caller stop observed",
        )?;
    }
    Ok(())
}
