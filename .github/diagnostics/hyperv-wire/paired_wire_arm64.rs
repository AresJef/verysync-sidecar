use super::*;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

const ARM64_SHA: &str = "56ee421e3933e8d8bb164164f25cc0cf7626d13ba4ed30f8a2ee9b78b8d841fa";

#[derive(Debug, PartialEq, Eq)]
enum TrafficClassOutcome {
    Matching,
    ApprovedIpv6Default,
    Mismatch,
}

fn traffic_class_outcome(
    family: u8,
    requested: i64,
    observed: &BTreeSet<u8>,
) -> TrafficClassOutcome {
    if u8::try_from(requested)
        .is_ok_and(|octet| observed.contains(&octet) && (octet != 0 || observed.len() == 1))
    {
        TrafficClassOutcome::Matching
    } else if family == 6
        && matches!(requested, 16 | 32)
        && observed.len() == 1
        && observed.contains(&0)
    {
        TrafficClassOutcome::ApprovedIpv6Default
    } else {
        TrafficClassOutcome::Mismatch
    }
}

#[cfg(test)]
mod traffic_class_tests {
    use super::*;

    #[test]
    fn only_approved_ipv6_nonzero_requests_accept_an_all_zero_observation() {
        use TrafficClassOutcome::*;
        for octet in [16, 32] {
            assert_eq!(
                traffic_class_outcome(4, octet, &BTreeSet::from([0])),
                Mismatch
            );
            assert_eq!(
                traffic_class_outcome(4, octet, &BTreeSet::from([octet as u8])),
                Matching
            );
            assert_eq!(
                traffic_class_outcome(6, octet, &BTreeSet::from([octet as u8])),
                Matching
            );
            assert_eq!(
                traffic_class_outcome(6, octet, &BTreeSet::from([0])),
                ApprovedIpv6Default
            );
            assert_eq!(
                traffic_class_outcome(6, octet, &BTreeSet::from([0, 8])),
                Mismatch
            );
            assert_eq!(traffic_class_outcome(6, octet, &BTreeSet::new()), Mismatch);
        }
        assert_eq!(traffic_class_outcome(4, 0, &BTreeSet::from([0])), Matching);
        assert_eq!(traffic_class_outcome(6, 0, &BTreeSet::from([0])), Matching);
        assert_eq!(
            traffic_class_outcome(6, 0, &BTreeSet::from([0, 8])),
            Mismatch
        );
        assert_eq!(traffic_class_outcome(6, 48, &BTreeSet::from([0])), Mismatch);
    }
}

struct Relay {
    child: Child,
    lines: mpsc::Receiver<std::io::Result<String>>,
}

impl Relay {
    fn start(
        tool: &Path,
        dll: &Path,
        adapter: &std::ffi::OsStr,
        family: u8,
        target: u16,
    ) -> Result<Self> {
        let mut child = Command::new(tool)
            .arg(dll)
            .arg(adapter)
            .arg(family.to_string())
            .arg(target.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()?;
        let printed = child.stdout.take().ok_or("missing relay stdout")?;
        let (sender, lines) = mpsc::sync_channel(4);
        thread::spawn(move || {
            for line in BufReader::new(printed).lines().take(4) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let relay = Self { child, lines };
        let ready = relay.next("ARM64_TUN_RELAY_READY ")?;
        ensure(
            number(&ready, "family=")? == u16::from(family)
                && number(&ready, "native_receiver_port=")? == target,
            "independent relay did not bind the exact requested case",
        )?;
        Ok(relay)
    }

    fn next(&self, marker: &str) -> Result<String> {
        let line = self.lines.recv_timeout(Duration::from_secs(10))??;
        ensure(
            line.len() <= 2048 && line.starts_with(marker),
            "missing exact bounded relay receipt",
        )?;
        println!("{line}");
        Ok(line)
    }

    fn finish(&mut self, front: u16, upstream: u16) -> Result<BTreeSet<u8>> {
        let line = self.next("ARM64_TUN_RELAY_CLOSED ")?;
        ensure(
            number(&line, "source_port=")? == front
                && number(&line, "upstream_source_port=")? == upstream
                && value(&line, "tcp_bytes=")?.parse::<usize>()? >= SIZE
                && value(&line, "packets=")?.parse::<usize>()? > 0,
            "relay did not close its actual observed data flow",
        )?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(exit) = self.child.try_wait()? {
                ensure(exit.success(), "independent relay exit was not normal")?;
                break;
            }
            if Instant::now() >= deadline {
                return Err("the exact relay did not exit after its receipt".into());
            }
            thread::sleep(Duration::from_millis(20));
        }
        let list = line
            .split_once(" octets={")
            .and_then(|(_, rest)| rest.strip_suffix('}'))
            .ok_or("missing captured original IP octets")?;
        list.split(", ")
            .map(|entry| {
                let (octet, count) = entry.split_once(": ").ok_or("invalid observed class")?;
                ensure(count.parse::<usize>()? > 0, "empty observed class")?;
                Ok(octet.parse::<u8>()?)
            })
            .collect()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn value<'a>(line: &'a str, field: &str) -> Result<&'a str> {
    line.split_ascii_whitespace()
        .find_map(|part| part.strip_prefix(field))
        .filter(|part| !part.is_empty())
        .ok_or_else(|| format!("missing relay field {field}").into())
}

fn number(line: &str, field: &str) -> Result<u16> {
    Ok(value(line, field)?.parse()?)
}

fn owned_tcp(pid: u32, peer: SocketAddr, local_port: u16) -> Result {
    let query = format!(
        "$match = @(Get-NetTCPConnection -State Established -OwningProcess {pid} -LocalPort {local_port} -RemotePort {} -RemoteAddress '{}' -ErrorAction SilentlyContinue); if ($match.Count -ne 1) {{ exit 1 }}",
        peer.port(), peer.ip()
    );
    let output = Command::new("pwsh.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &query])
        .output()?;
    ensure(
        output.status.success(),
        "the native Windows sender does not own the captured flow",
    )
}

async fn one_case(
    case: (u8, i64),
    root: &Path,
    binary: &Path,
    relay_tool: &Path,
    dll: &Path,
    adapter: &std::ffi::OsStr,
) -> Result<TrafficClassOutcome> {
    let (_, dest) = addresses(case.0)?;
    let wire_ip = SocketAddr::new(dest, 47529);
    let lease = TcpListener::bind(("127.0.0.1", 0))?;
    let backend = lease.local_addr()?;
    drop(lease);
    let source = root.join("source");
    let received = root.join("received");
    fs::create_dir_all(&source)?;
    fs::create_dir_all(&received)?;
    let bytes = sample(case);
    fs::write(source.join(FILE), &bytes)?;

    let mut a = ManagedInstance::start(managed(&root.join("a"), binary, ARM64_SHA)?).await?;
    let mut b = ManagedInstance::start(managed(&root.join("b"), binary, ARM64_SHA)?).await?;
    preconfigure(a.client(), None).await?;
    preconfigure(b.client(), Some(backend)).await?;
    let (aid, bid) = (
        a.client().instance().device_id.clone(),
        b.client().instance().device_id.clone(),
    );
    let (a_keys, b_keys) = (credentials(&a)?, credentials(&b)?);
    let (a_before, b_before) = (
        a.client().configuration().await?,
        b.client().configuration().await?,
    );
    ensure(
        a.client()
            .update_general_options(&GeneralOptionsPatch::default().traffic_class(case.1))
            .await?
            .requested_fields_match,
        "native traffic class write did not match",
    )?;
    a.restart(Duration::from_secs(30)).await?;
    b.restart(Duration::from_secs(25)).await?;
    ensure(
        a.client().general_options().await?.traffic_class == Some(case.1),
        "native traffic class was not retained through restart",
    )?;
    listener(b.client(), backend).await?;
    let mut relay = Relay::start(relay_tool, dll, adapter, case.0, backend.port())?;
    let keys = a.client().generate_share().await?;
    let write = a.client().validate_share_key(&keys.read_write_key).await?;
    let read = b.client().validate_share_key(&keys.read_only_key).await?;
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(write, TargetPath::local(&source)).paused(true))
        .await?
        .configuration
        .id;
    let bf = b
        .client()
        .join_folder(&JoinFolderOptions::new(read, TargetPath::local(&received)).paused(true))
        .await?
        .configuration
        .id;
    add_peer(b.client(), &aid, "dynamic".to_string()).await?;
    add_peer(a.client(), &bid, format!("tcp://{wire_ip}")).await?;
    a.client().share_folder_with(&af, &bid).await?;
    b.client().share_folder_with(&bf, &aid).await?;
    b.client().resume_folder(&bf).await?;
    a.client().resume_folder(&af).await?;
    file_received(b.client(), &bf, &received.join(FILE), &bytes).await?;

    let open = relay.next("ARM64_TUN_RELAY_OPEN ")?;
    let front = number(&open, "source_port=")?;
    let upstream = number(&open, "upstream_source_port=")?;
    ensure(
        connected(a.client(), &bid, PeerConnectionType::TcpClient).await? == wire_ip
            && connected(b.client(), &aid, PeerConnectionType::TcpServer).await?
                == SocketAddr::new(backend.ip(), upstream),
        "the real authenticated pair did not match both measured TCP halves",
    )?;
    owned_tcp(a.process_id(), wire_ip, front)?;
    retained(&a_before, &a.client().configuration().await?)?;
    retained(&b_before, &b.client().configuration().await?)?;
    ensure(
        a.client().system_status().await?.device_id == aid
            && b.client().system_status().await?.device_id == bid
            && credentials(&a)? == a_keys
            && credentials(&b)? == b_keys,
        "the two independent identities changed",
    )?;
    closed(&mut a).await?;
    closed(&mut b).await?;
    let classes = relay.finish(front, upstream)?;
    ensure(
        fs::read(source.join(FILE))? == bytes && fs::read(received.join(FILE))? == bytes,
        "the actual source and received files must survive shutdown",
    )?;
    let outcome = traffic_class_outcome(case.0, case.1, &classes);
    println!(
        "ARM64_VS_WIRE_CASE {}",
        serde_json::json!({
            "family":case.0,"requested":case.1,"source_port":front,"receiver_upstream_port":upstream,
            "observed_octets":classes,"expected_octet_seen":outcome == TrafficClassOutcome::Matching,
            "approved_ipv6_default":outcome == TrafficClassOutcome::ApprovedIpv6Default,
            "accepted":outcome != TrafficClassOutcome::Mismatch,
            "sample_bytes":SIZE,"sample_sha256":digest(&bytes),
            "authenticated_both_halves":true,"both_owned_normal_exit":true,"data_and_identity_retained":true,
        })
    );
    Ok(outcome)
}

pub(super) async fn exercise(relay: &Path, dll: &Path, adapter: &std::ffi::OsStr) -> Result {
    let git_ref = std::env::var("GITHUB_REF").unwrap_or_default();
    let candidate_ref = git_ref
        .strip_prefix("refs/heads/ci/formal-candidate/")
        .is_some_and(|name| !name.is_empty() && !name.starts_with('/'));
    ensure(
        cfg!(all(windows, target_arch = "aarch64"))
            && std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
            && std::env::var("RUNNER_ENVIRONMENT").as_deref() == Ok("github-hosted")
            && std::env::var("GITHUB_REPOSITORY").as_deref() == Ok("AresJef/verysync-sidecar")
            && (candidate_ref || git_ref == "refs/heads/verify/r24/windows-arm64-verysync-wire"),
        "use only the owned native Windows ARM64 job",
    )?;
    let binary =
        PathBuf::from(std::env::var_os("VERYSYNC_TEST_BINARY").ok_or("fixed owned core required")?);
    let temp = std::env::var_os("RUNNER_TEMP").ok_or("private runner directory required")?;
    let root = tempfile::Builder::new()
        .prefix("vs-arm64-wire-")
        .tempdir_in(temp)?;
    let mut strict_cases = 0;
    let mut approved_ipv6_defaults = 0;
    for case in CASES {
        let outcome = one_case(
            case,
            &root.path().join(format!("{}-{}", case.0, case.1)),
            &binary,
            relay,
            dll,
            adapter,
        )
        .await?;
        match outcome {
            TrafficClassOutcome::Matching => strict_cases += 1,
            TrafficClassOutcome::ApprovedIpv6Default => approved_ipv6_defaults += 1,
            TrafficClassOutcome::Mismatch => {}
        }
    }
    root.close()?;
    let strict = strict_cases == CASES.len();
    let passed = strict_cases + approved_ipv6_defaults == CASES.len();
    println!("ARM64_VS_WIRE_GATE strict_octets_match={strict} strict_cases={strict_cases} approved_ipv6_defaults={approved_ipv6_defaults} six_native_cases_accepted={passed}");
    ensure(
        passed,
        "the fixed ARM64 traffic does not match the required native outcomes",
    )
}
