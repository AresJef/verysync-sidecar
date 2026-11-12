//! Execute actual compiled examples against an exact independent official engine.

#[path = "common/engine_fixture.rs"]
#[allow(dead_code)] // This execution target intentionally uses a subset of the shared fixture API.
mod engine_fixture;

use engine_fixture::{EngineFixture, TestResult};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

struct OwnedExample(Option<Child>);
impl Drop for OwnedExample {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
async fn execute(
    directory: &Path,
    name: &str,
    args: &[OsString],
    instance: &EngineFixture,
) -> TestResult<Output> {
    let mut executable = directory.join(name);
    if cfg!(windows) {
        executable.set_extension("exe");
    }
    if !executable.is_file() {
        return Err("compiled example is missing; run prepare-test-examples.py explicitly".into());
    }
    let child = Command::new(executable)
        .args(args)
        .env("VERYSYNC_EXAMPLE_API_KEY", instance.api_key())
        .current_dir(instance.state_dir())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut owned = OwnedExample(Some(child));
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if owned
            .0
            .as_mut()
            .ok_or("example child missing")?
            .try_wait()?
            .is_some()
        {
            break;
        }
        if Instant::now() >= deadline {
            return Err(
                "compiled example exceeded deadline; its exact child is being reaped".into(),
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let output = owned
        .0
        .take()
        .ok_or("example child missing")?
        .wait_with_output()?;
    if !output.status.success() {
        let mut text =
            String::from_utf8_lossy(&output.stderr).replace(instance.api_key(), "[redacted]");
        if text.len() > 8192 {
            text = "example stderr exceeded the bounded diagnostic limit".to_owned();
        }
        return Err(format!("compiled example failed: {}: {text}", output.status).into());
    }
    Ok(output)
}
fn connection_args(instance: &EngineFixture) -> Vec<OsString> {
    #[cfg(unix)]
    let args = vec![
        OsString::from("socket"),
        instance.state_dir().join("gui.sock").into_os_string(),
    ];
    #[cfg(windows)]
    let args = vec![
        OsString::from("http"),
        OsString::from(format!("http://{}", instance.management_address())),
    ];
    args
}

#[tokio::test]
async fn compiled_examples_query_control_and_keep_synthetic_files() -> TestResult {
    use sha2::{Digest, Sha256};
    use verysync_sidecar::{
        ApiKey, Client, ConnectOptions, DeviceId, FolderId, ManagementEndpoint,
    };
    let directory = PathBuf::from(
        std::env::var_os("VERYSYNC_TEST_EXAMPLE_DIR")
            .ok_or("VERYSYNC_TEST_EXAMPLE_DIR is required; explicitly build examples first")?,
    );
    for name in ["connect_existing", "create_folder", "manage_existing"] {
        let mut path = directory.join(name);
        if cfg!(windows) {
            path.set_extension("exe");
        }
        if !path.is_file() {
            return Err("required compiled example is missing before engine startup".into());
        }
    }
    let mut instance = EngineFixture::start().await?;
    let verified:TestResult<serde_json::Value>=async {
        let mut args=connection_args(&instance);args.push(OsString::from(instance.device_id()));
        let connected=execute(&directory,"connect_existing",&args,&instance).await?;
        let first_path=instance.state_dir().join("example create retained 中文");std::fs::create_dir(&first_path)?;
        let first_file=first_path.join("original.txt");std::fs::write(&first_file,b"sample for create example\n")?;
        let first_hash=Sha256::digest(std::fs::read(&first_file)?);
        let create_id=FolderId::parse("sidecar-compiled-create")?;
        let mut create_args=args.clone();create_args.push(OsString::from(create_id.as_str()));create_args.push(first_path.into_os_string());
        let created=execute(&directory,"create_folder",&create_args,&instance).await?;
        let managed_path=instance.state_dir().join("example manage retained 中文");std::fs::create_dir(&managed_path)?;
        let managed_file=managed_path.join("original.txt");std::fs::write(&managed_file,b"sample for management example\n")?;
        let managed_hash=Sha256::digest(std::fs::read(&managed_file)?);
        let managed_id=FolderId::parse("sidecar-compiled-manage")?;
        let mut manage_args=args;manage_args.push(OsString::from(managed_id.as_str()));manage_args.push(managed_path.into_os_string());
        let managed=execute(&directory,"manage_existing",&manage_args,&instance).await?;
        #[cfg(unix)]
        let endpoint=ManagementEndpoint::unix_socket(instance.state_dir().join("gui.sock"))?;
        #[cfg(windows)]
        let endpoint=ManagementEndpoint::http(&format!("http://{}",instance.management_address()))?;
        let client=Client::connect(ConnectOptions::new(endpoint,ApiKey::new(instance.api_key())?).expected_device_id(DeviceId::parse(instance.device_id())?)).await?;
        let retained=client.folder(&create_id).await?;
        let removed=matches!(client.folder(&managed_id).await,Err(verysync_sidecar::Error::FolderNotFound{..}));
        let alive=client.system_status().await?.device_id.as_str()==instance.device_id();
        Ok(serde_json::json!({"connect_executable_ran":String::from_utf8_lossy(&connected.stdout).contains("Connected:"),"create_executable_ran":String::from_utf8_lossy(&created.stdout).contains("Registered paused folder:"),"create_actual_configuration_paused":retained.paused,"create_sample_sha_unchanged":Sha256::digest(std::fs::read(first_file)?)==first_hash,"manage_executable_ran":String::from_utf8_lossy(&managed.stdout).contains("Managed configuration workflow:"),"manage_actual_configuration_absent":removed,"manage_sample_sha_unchanged":Sha256::digest(std::fs::read(managed_file)?)==managed_hash,"borrowed_engine_still_running":alive,"three_example_children_exited":true}))
    }.await;
    let stopped = instance.shutdown().await;
    let report = verified?;
    println!("compiled example evidence: {report}");
    assert!(stopped?.success());
    for (name, value) in report.as_object().ok_or("missing example evidence")? {
        assert_eq!(value, &serde_json::json!(true), "{name}");
    }
    Ok(())
}
