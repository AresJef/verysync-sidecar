//! Pure managed inputs never execute programs or inspect an existing instance.

use std::path::PathBuf;
use std::time::Duration;
use verysync_sidecar::{Error, LocalProgram, ManagedOptions, ManagementEndpoint};

fn root() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/synthetic-managed-state")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\synthetic-managed-state")
    }
}

#[test]
fn managed_inputs_are_explicit_native_values() -> verysync_sidecar::Result<()> {
    let state = root();
    let program = LocalProgram::new(state.join("program"))?.expected_sha256([7; 32]);
    let endpoint = ManagementEndpoint::http("http://127.0.0.1:43219")?;
    let options = ManagedOptions::new(program.clone(), &state, endpoint.clone())?;
    assert_eq!(options.state_directory(), state);
    assert_eq!(options.program().path(), program.path());
    assert_eq!(options.management_endpoint(), &endpoint);
    assert!(options.startup_timeout(Duration::ZERO).is_err());
    Ok(())
}

#[test]
fn managed_inputs_reject_ambient_or_remote_addresses() -> verysync_sidecar::Result<()> {
    assert!(LocalProgram::new("verysync").is_err());
    let program = LocalProgram::new(root().join("program"))?;
    for address in [
        "http://localhost:43219",
        "http://192.0.2.1:43219",
        "http://127.0.0.1:43219/proxy",
    ] {
        assert!(matches!(
            ManagedOptions::new(program.clone(), root(), ManagementEndpoint::http(address)?),
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    assert!(ManagedOptions::new(
        program,
        "relative-state",
        ManagementEndpoint::http("http://127.0.0.1:43219")?
    )
    .is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn managed_socket_is_contained_in_the_dedicated_state() -> verysync_sidecar::Result<()> {
    let state = root();
    let program = LocalProgram::new(state.join("program"))?;
    let expected = ManagementEndpoint::unix_socket(state.join("gui.sock"))?;
    ManagedOptions::new(program.clone(), &state, expected)?;
    let outside = ManagementEndpoint::unix_socket("/synthetic-other/gui.sock")?;
    assert!(ManagedOptions::new(program, state, outside).is_err());
    Ok(())
}

#[test]
fn managed_https_is_explicit_and_requires_the_tls_feature() -> verysync_sidecar::Result<()> {
    let result = ManagedOptions::new(
        LocalProgram::new(root().join("program"))?,
        root(),
        ManagementEndpoint::http("https://127.0.0.1:43219/")?,
    );
    #[cfg(feature = "tls")]
    assert!(result.is_ok());
    #[cfg(not(feature = "tls"))]
    assert!(matches!(result, Err(Error::UnsupportedTransport { .. })));
    Ok(())
}
