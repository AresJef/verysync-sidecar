//! Opt-in native lifecycle regressions with explicitly prepared test programs.
use super::*;
use crate::{DatabaseCommand, LocalProgram, ManagementEndpoint, StateBackup, StateBackupOptions};
use std::future::{poll_fn, Future};
use std::net::{Ipv4Addr, TcpListener};
use std::task::Poll;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn source(binary_variable: &str, sha_variable: &str) -> TestResult<LocalProgram> {
    let program =
        std::env::var_os(binary_variable).ok_or("an isolated test program is required")?;
    let digest = std::env::var(sha_variable)?;
    let mut sha = [0; 32];
    if digest.len() != 64 {
        return Err("an explicit test program SHA-256 is required".into());
    }
    for (index, byte) in sha.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16)?;
    }
    Ok(LocalProgram::new(program)?.expected_sha256(sha))
}

fn baseline() -> TestResult<LocalProgram> {
    source("VERYSYNC_TEST_BINARY", "VERYSYNC_TEST_BINARY_SHA256")
}

fn endpoint(listener: &TcpListener) -> TestResult<ManagementEndpoint> {
    Ok(ManagementEndpoint::http(&format!(
        "http://{}",
        listener.local_addr()?
    ))?)
}

fn settings(program: LocalProgram, state: &Path) -> TestResult<ManagedOptions> {
    let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(ManagedOptions::new(program, state, endpoint(&socket)?)?)
}

async fn next_exit(mut receiver: watch::Receiver<Option<ManagedExit>>) -> TestResult<ManagedExit> {
    Ok(tokio::time::timeout(Duration::from_secs(15), async move {
        loop {
            if let Some(report) = receiver.borrow_and_update().as_ref().cloned() {
                return Ok::<_, watch::error::RecvError>(report);
            }
            receiver.changed().await?;
        }
    })
    .await??)
}

async fn pending_once<F: Future>(mut future: std::pin::Pin<&mut F>) {
    assert!(poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx).is_pending())).await);
}

#[tokio::test]
#[ignore = "requires the explicitly prepared isolated engine fixture"]
async fn deep_repair_queued_shutdown_never_dispatches_to_the_replacement() -> TestResult {
    let fixture = tempfile::tempdir()?;
    let state = fixture.path().join("state");
    let settings = settings(baseline()?, &state)?;
    let mut first = ManagedInstance::start(settings.clone()).await?;
    let old_pid = first.process_id();
    let key = bootstrap::test_persisted_key(first.state_directory())?;
    let identity = first.client().instance().device_id.clone();
    let direct = Client::connect(
        ConnectOptions::new(settings.endpoint.clone(), key.clone())
            .expected_device_id(identity.clone()),
    )
    .await?;
    let queued_client = first.client().clone();
    let gate = queued_client.test_hold_write_gate().await;
    let exit = first.exit.clone();
    let mut queued = std::pin::pin!(first.shutdown(Duration::from_secs(45)));
    pending_once(queued.as_mut()).await;
    direct.request_shutdown().await?;
    let old = next_exit(exit).await?;
    assert!(old.tree_stopped && old.state_released && !old.forced && old.code == Some(0));
    assert_eq!(direct.test_shutdown_calls(), 1);
    let mut next = ManagedInstance::start(settings).await?;
    let new_pid = next.process_id();
    assert_ne!(new_pid, old_pid);
    assert_eq!(next.client().instance().device_id, identity);
    assert!(bootstrap::test_persisted_key(next.state_directory())?.header() == key.header());
    drop(gate);
    assert_eq!(queued.await?, old);
    assert_eq!(queued_client.test_shutdown_calls(), 0);
    next.client().system_status().await?;
    assert_eq!(next.shutdown(Duration::from_secs(10)).await?.code, Some(0));
    assert_eq!(next.client().test_shutdown_calls(), 1);
    println!("owned shutdown evidence: old_pid={old_pid}, new_pid={new_pid}, endpoint_identity_and_api_key_reused=true, stale_posts=0, normal_posts=1, both_exited=true");
    Ok(())
}

#[tokio::test]
#[ignore = "requires the explicitly prepared isolated engine fixture"]
async fn deep_repair_force_wait_distinguishes_normal_forced_and_missing() -> TestResult {
    let root = tempfile::tempdir()?;
    let path = root.path().join("state");
    let settings = settings(baseline()?, &path)?;
    let mut instance = ManagedInstance::start(settings.clone()).await?;
    let normal = instance.shutdown(Duration::from_secs(10)).await?;
    let (send, closing) = mpsc::channel();
    drop(closing);
    instance._owner = send;
    let (report, observed) = watch::channel(None);
    instance.exit = observed;
    {
        let mut wait = std::pin::pin!(instance.force_stop(Duration::from_secs(5)));
        pending_once(wait.as_mut()).await;
        report.send(Some(normal.clone()))?;
        assert_eq!(wait.await?, normal);
    }
    drop(report);
    let (missing, observed) = watch::channel(None);
    instance.exit = observed;
    drop(missing);
    assert!(matches!(
        instance.force_stop(Duration::from_secs(5)).await,
        Err(Error::ManagedFailure {
            reason: "owner ended without an exit report"
        })
    ));
    let mut next = ManagedInstance::start(settings).await?;
    let forced = next.force_stop(Duration::from_secs(10)).await?;
    assert!(forced.forced && forced.tree_stopped && forced.state_released);
    assert_eq!(next.client().test_shutdown_calls(), 0);
    println!("force-stop evidence: normal-report race distinguished from missing report and actual forced exit, no API posts");
    Ok(())
}

async fn rejects_stale_owner(old: &mut ManagedInstance, destination: &Path) -> TestResult {
    let refused = old
        .backup_state(StateBackupOptions::new(destination)?)
        .await;
    assert!(
        matches!(
            refused,
            Err(Error::StateBackupRejected {
                reason: "state no longer matches this normally stopped owner and program"
            })
        ),
        "{refused:?}"
    );
    assert!(!destination.exists());
    assert!(matches!(
        old.run_database_command(DatabaseCommand::Statistics, Duration::from_secs(5))
            .await,
        Err(Error::ManagedFailure {
            reason: "private state does not match this stopped owner and program"
        })
    ));
    Ok(())
}

#[tokio::test]
#[ignore = "requires the explicitly prepared isolated engine fixture"]
async fn deep_repair_stopped_provenance_tracks_the_new_program_and_failed_run() -> TestResult {
    let fixture = tempfile::tempdir()?;
    let state = fixture.path().join("state");
    let previous_program = source(
        "VERYSYNC_TEST_UPGRADE_SOURCE_BINARY",
        "VERYSYNC_TEST_UPGRADE_SOURCE_SHA256",
    )?;
    let mut old = ManagedInstance::start(
        settings(previous_program, &state)?.version_policy(crate::VersionPolicy::AllowUnverified),
    )
    .await?;
    let previous = old.program_info().sha256;
    let sample = b"synthetic stopped-generation sample";
    std::fs::write(state.join("sample.bin"), sample)?;
    assert_eq!(old.shutdown(Duration::from_secs(10)).await?.code, Some(0));
    let program = baseline()?;
    let mut current = ManagedInstance::start(settings(program.clone(), &state)?).await?;
    assert_ne!(current.program_info().sha256, previous);
    assert_eq!(
        current.shutdown(Duration::from_secs(10)).await?.code,
        Some(0)
    );
    rejects_stale_owner(&mut old, &fixture.path().join("rejected-previous")).await?;
    for n in 1..=2 {
        let target = fixture.path().join(format!("snapshot-{n}"));
        let backup = current
            .backup_state(StateBackupOptions::new(&target)?)
            .await?;
        let opened = StateBackup::open(
            &target,
            backup.info().manifest_sha256,
            Duration::from_secs(10),
        )
        .await?;
        assert_eq!(
            opened.info().source_program.sha256,
            current.program_info().sha256
        );
        assert_eq!(
            opened.info().source_program.version,
            current.program_info().version
        );
        assert_eq!(
            opened.info().device_id,
            current.client().instance().device_id
        );
        let restored = fixture.path().join(format!("restored-{n}"));
        opened
            .restore_to(&restored, Duration::from_secs(10))
            .await?;
        assert_eq!(std::fs::read(restored.join("sample.bin"))?, sample);
    }
    let bad = program.clone().expected_sha256([0; 32]);
    assert!(matches!(
        ManagedInstance::start(settings(bad, &state)?).await,
        Err(Error::ProgramRejected { .. })
    ));
    rejects_stale_owner(&mut current, &fixture.path().join("rejected-after-failure")).await?;
    let mut entered = ManagedInstance::start(settings(program, &state)?).await?;
    assert!(entered.force_stop(Duration::from_secs(10)).await?.forced);
    let destination = fixture.path().join("rejected-after-force");
    assert!(current
        .backup_state(StateBackupOptions::new(&destination)?)
        .await
        .is_err());
    assert!(!destination.exists());
    assert!(entered
        .backup_state(StateBackupOptions::new(&destination)?)
        .await
        .is_err());
    assert!(!destination.exists());
    assert_eq!(std::fs::read(state.join("sample.bin"))?, sample);
    println!("stopped provenance evidence: different official program digest, two reopened and restored snapshots, no stale snapshot or maintenance, failed selection and forced stop covered");
    Ok(())
}

#[tokio::test]
#[ignore = "requires the explicitly prepared isolated engine fixture"]
async fn deep_repair_cancelled_preparation_never_recertifies_the_previous_owner() -> TestResult {
    use crate::managed::state::{StateLease, GENERATION};

    let root = tempfile::tempdir()?;
    let path = root.path().join("state");
    let program = baseline()?;
    let mut first = ManagedInstance::start(settings(program.clone(), &path)?).await?;
    let exit = first.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced);
    let generation_file = path.join(GENERATION);
    let before = std::fs::read(&generation_file)?;
    let blocked = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let options = ManagedOptions::new(program, &path, endpoint(&blocked)?)?
        .startup_timeout(Duration::from_secs(30))?;
    let attempt = tokio::spawn(ManagedInstance::start(options));
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if std::fs::read(&generation_file).is_ok_and(|contents| contents != before) {
                break;
            }
            assert!(!attempt.is_finished());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    attempt.abort();
    assert!(attempt.await.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match StateLease::acquire(&path) {
                Ok(lease) => {
                    drop(lease);
                    break Ok::<_, Error>(());
                }
                Err(Error::ManagedStateInUse { .. }) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(other) => break Err(other),
            }
        }
    })
    .await??;
    rejects_stale_owner(&mut first, &root.path().join("rejected-after-cancel")).await?;
    println!("cancelled preparation evidence: new pending run observed, same fixture lease reopened, stale backup and CLI refused");
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires the explicitly prepared isolated engine fixture"]
async fn deep_repair_pipe_is_refused_before_start_and_lease_can_be_reacquired() -> TestResult {
    let fixture = tempfile::tempdir()?;
    let pipe = fixture.path().join("not-a-program");
    assert!(std::process::Command::new("/usr/bin/mkfifo")
        .arg(&pipe)
        .status()?
        .success());
    let state = fixture.path().join("state");
    let wrong =
        settings(LocalProgram::new(&pipe)?, &state)?.startup_timeout(Duration::from_secs(4))?;
    let started = Instant::now();
    assert!(matches!(
        ManagedInstance::start(wrong).await,
        Err(Error::ProgramRejected {
            reason: "executable must be a regular file"
        })
    ));
    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(!state.join("key.pem").exists());
    assert!(!state.join("setting.dat").exists());
    let mut core = ManagedInstance::start(settings(baseline()?, &state)?).await?;
    core.client().system_status().await?;
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && exit.code == Some(0));
    println!("executable selection evidence: FIFO rejected before the deadline with no native state, same lease reopened with pinned program, clean exit");
    Ok(())
}

#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore = "requires the explicitly prepared isolated engine fixture"]
async fn deep_repair_macos_state_and_backup_refuse_inherited_read_grants() -> TestResult {
    use std::os::unix::fs::MetadataExt;
    use std::process::Command;

    let fixture = tempfile::tempdir()?;
    let parent = fixture.path().join("with-inheritance");
    crate::managed::native::create_directory(&parent)?;
    assert!(Command::new("/bin/chmod")
        .args([
            "+a",
            "everyone allow list,read,file_inherit,directory_inherit"
        ])
        .arg(&parent)
        .status()?
        .success());
    let before = Command::new("/bin/ls").arg("-led").arg(&parent).output()?;
    assert!(before.status.success());
    let denied_state = parent.join("state");
    assert!(matches!(
        ManagedInstance::start(settings(baseline()?, &denied_state)?).await,
        Err(Error::LocalIo { .. })
    ));
    assert!(!denied_state.join("key.pem").exists());
    assert!(!denied_state.join(".verysync-sidecar-lease").exists());
    let state = fixture.path().join("private");
    let mut core = ManagedInstance::start(settings(baseline()?, &state)?).await?;
    let sample = b"synthetic file with a private fingerprint";
    std::fs::write(state.join("sample.bin"), sample)?;
    assert_eq!(core.shutdown(Duration::from_secs(10)).await?.code, Some(0));
    let rejected_backup = parent.join("backup");
    assert!(matches!(
        core.backup_state(StateBackupOptions::new(&rejected_backup)?)
            .await,
        Err(Error::LocalIo { .. })
    ));
    assert!(!rejected_backup.join("sample.bin").exists());
    let clean_backup = fixture.path().join("private-backup");
    let backed_up = core
        .backup_state(StateBackupOptions::new(&clean_backup)?)
        .await?;
    let restored = fixture.path().join("restored");
    backed_up
        .restore_to(&restored, Duration::from_secs(10))
        .await?;
    assert_eq!(std::fs::read(restored.join("sample.bin"))?, sample);
    assert_eq!(std::fs::read(state.join("sample.bin"))?, sample);
    let after = Command::new("/bin/ls").arg("-led").arg(&parent).output()?;
    assert!(after.status.success());
    assert_eq!(std::fs::metadata(&parent)?.mode() & 0o777, 0o700);
    let acl_lines = |output: Vec<u8>| {
        String::from_utf8_lossy(&output)
            .lines()
            .skip(1)
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    assert_eq!(acl_lines(before.stdout), acl_lines(after.stdout));
    println!("macOS lifecycle ACL evidence: refused state before locks or keys, refused destination before copied bytes, ordinary backup and file-preserving restore passed");
    Ok(())
}
