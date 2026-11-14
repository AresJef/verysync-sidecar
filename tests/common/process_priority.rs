//! Test-only native priority observation for the exact owned core/group.
type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub async fn observe(root: u32) -> TestResult<Vec<String>> {
    tokio::task::spawn_blocking(move || observe_blocking(root)).await?
}

#[cfg(unix)]
fn observe_blocking(root: u32) -> TestResult<Vec<String>> {
    let output = std::process::Command::new("ps")
        .args(["-A", "-o", "pid=,pgid=,nice="])
        .output()?;
    if !output.status.success() {
        return Err("owned group priority observation failed".into());
    }
    let mut priorities = Vec::new();
    let mut root_seen = false;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() == 3 && fields[1].parse::<u32>().ok() == Some(root) {
            root_seen |= fields[0].parse::<u32>().ok() == Some(root);
            fields[2].parse::<i32>()?;
            priorities.push(fields[2].to_owned());
        }
    }
    if !root_seen || priorities.is_empty() {
        return Err("exact owned priority group absent".into());
    }
    Ok(priorities)
}

#[cfg(windows)]
fn observe_blocking(root: u32) -> TestResult<Vec<String>> {
    use std::os::windows::process::CommandExt;
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(format!(
            "$ErrorActionPreference='Stop'; (Get-Process -Id {root}).PriorityClass.ToString()"
        ))
        .creation_flags(0x08000000)
        .output()?;
    if !output.status.success() {
        return Err("exact owned priority-class observation failed".into());
    }
    let value = String::from_utf8(output.stdout)?.trim().to_owned();
    if value.is_empty() {
        return Err("owned priority class absent".into());
    }
    Ok(vec![value])
}
