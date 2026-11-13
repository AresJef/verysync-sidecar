//! Shared private fixed-program selection for native public API cases.
use std::path::{Path, PathBuf};
use std::time::Duration;
use verysync_sidecar::{LocalProgram, ManagedOptions, ManagementEndpoint};
pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub fn options(state: &Path) -> TestResult<ManagedOptions> {
    let path =
        std::env::var_os("VERYSYNC_TEST_BINARY").ok_or("explicit private program required")?;
    let hex = std::env::var("VERYSYNC_TEST_BINARY_SHA256")?;
    if hex.len() != 64 {
        return Err("explicit fixed program digest required".into());
    }
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)?;
    }
    #[cfg(unix)]
    let endpoint = ManagementEndpoint::unix_socket(state.join("gui.sock"))?;
    #[cfg(windows)]
    let endpoint = {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        ManagementEndpoint::http(&format!("http://{}/", listener.local_addr()?))?
    };
    Ok(ManagedOptions::new(
        LocalProgram::new(PathBuf::from(path))?.expected_sha256(digest),
        state,
        endpoint,
    )?
    .startup_timeout(Duration::from_secs(25))?)
}
