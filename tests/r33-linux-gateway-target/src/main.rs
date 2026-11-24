//! The isolated target for an owned native remote-management test.

mod engine_hash;

use engine_hash::ENGINE_HASH;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{self, BufRead, Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use verysync_sidecar::{
    ApiKey, Client, CreateDeviceOptions, CreateFolderOptions, DeviceId, DevicePatch, FolderId,
    FolderPatch, LocalProgram, ManagedInstance, ManagedOptions, ManagementEndpoint, RawMethod,
    RawRequest, RequestEffect, TargetPath, BASELINE_ENGINE_VERSION,
};

type Check<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const INITIAL: &str = "Owned gateway baseline";
const CHANGED: &str = "Owned gateway change";
const FRAME: u64 = 4096;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Command {
    Register { peer: String },
    Allow,
    State,
    Restore,
    End,
}

fn take<T: serde::de::DeserializeOwned>() -> Check<Option<T>> {
    let mut line = vec![];
    let found = io::stdin()
        .lock()
        .by_ref()
        .take(FRAME + 1)
        .read_until(b'\n', &mut line)?;
    if found == 0 {
        return Ok(None);
    }
    if found as u64 > FRAME || !line.ends_with(b"\n") {
        return Err("The supplied frame exceeds its limit.".into());
    }
    let record = serde_json::from_slice(&line)?;
    line.fill(0);
    Ok(Some(record))
}

fn print(value: Value) -> Check {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, &value)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

fn fixture_port(raw: &str) -> Check<u16> {
    let port: u16 = raw.parse()?;
    if port < 1024 || port == 18886 {
        return Err("Choose an isolated non-default fixture port.".into());
    }
    Ok(port)
}

async fn pin(core: &mut ManagedInstance, data: SocketAddr, auxiliary: u16) -> Check {
    let identity = core.client().instance().device_id.clone();
    let own = format!("tcp://{data}");
    let result = core
        .client()
        .raw_request(
            &RawRequest::new(
                RawMethod::Patch,
                ["rest", "config", "options"],
                RequestEffect::MayModify,
            )?
            .json_body(&json!({
                "listenAddresses":[own],"localAnnounceEnabled":false,
                "globalAnnounceEnabled":false,"relaysEnabled":false,
                "natEnabled":false,"reconnectionIntervalS":5,
                "localTunnelAddress": format!("127.0.0.1:{auxiliary}")
            }))?,
        )
        .await?;
    if !(200..300).contains(&result.status()) {
        return Err("The dedicated P2P listener request failed.".into());
    }
    core.restart(Duration::from_secs(18)).await?;
    let now = core.client().network_configuration().await?;
    if core.client().instance().device_id != identity || now.listen_addresses != [own] {
        return Err("The target listener or identity was not confirmed after restart.".into());
    }
    Ok(())
}

struct Target {
    folder: FolderId,
    peer: Option<DeviceId>,
    samples: [PathBuf; 2],
    baseline: [Value; 2],
}

fn files(samples: &[PathBuf; 2]) -> Check<[Value; 2]> {
    let snapshot = |path: &Path| -> Check<Value> {
        let data = fs::read(path)?;
        Ok(json!({"bytes":data.len(),"sha256":format!("{:x}",Sha256::digest(&data))}))
    };
    Ok([snapshot(&samples[0])?, snapshot(&samples[1])?])
}

impl Target {
    async fn create(root: &Path, client: &Client, run: &str) -> Check<Self> {
        if !client.folders().await?.is_empty() {
            return Err("The target needs a separate empty configuration.".into());
        }
        let folder = FolderId::parse("r33-dedicated-gateway-target")?;
        let selected = root.join("selected");
        fs::create_dir(&selected)?;
        let samples = [selected.join("visible.txt"), root.join("outside.txt")];
        fs::write(&samples[0], format!("Owned gateway target sample {run}\n"))?;
        fs::write(&samples[1], b"An unrelated synthetic sentinel.\n")?;
        let baseline = files(&samples)?;
        client
            .create_folder(
                &CreateFolderOptions::new(folder.clone(), TargetPath::local(&selected))
                    .label(INITIAL)
                    .paused(true),
            )
            .await?;
        Ok(Self {
            folder,
            peer: None,
            samples,
            baseline,
        })
    }

    async fn observe(&self, client: &Client) -> Check<Value> {
        let selected = client.folder(&self.folder).await?;
        if selected.id != self.folder {
            return Err("The target returned another folder.".into());
        }
        let bytes = files(&self.samples)?;
        let link = match &self.peer {
            Some(peer) => {
                let settings = client.device(peer).await?;
                let current = client.connections().await?;
                let connection = current.connections.get(peer);
                json!({"allowed":settings.allow_tunnel,"connected":connection.is_some_and(|info|info.connected),
                       "reported_local":connection.and_then(|info|info.is_local),
                       "native_transport":connection.and_then(|info|info.connection_type.as_ref())
                           .map(|kind|format!("{kind:?}")),
                       "reported_address_sha256":connection.and_then(|info|info.address.as_ref())
                           .map(|address|format!("{:x}",Sha256::digest(address.as_bytes())))})
            }
            None => Value::Null,
        };
        Ok(
            json!({"ok":true,"label":selected.label,"paused":selected.paused,
                  "folder_exact":true,"files_match":bytes==self.baseline,
                  "before":self.baseline,"actual":bytes,"peer":link}),
        )
    }

    async fn register(&mut self, client: &Client, peer: DeviceId) -> Check<Value> {
        if self.peer.is_some() || peer == client.instance().device_id {
            return Err("Only one distinct, owned peer may be selected.".into());
        }
        let permit = DevicePatch::default()
            .addresses(vec!["dynamic".into()])
            .paused(false)
            .allow_tunnel(false);
        if !client
            .create_device(&CreateDeviceOptions::new(peer.clone()).settings(permit))
            .await?
            .requested_fields_match
        {
            return Err("The selected peer registration did not match.".into());
        }
        self.peer = Some(peer);
        self.observe(client).await
    }

    async fn grant(&self, client: &Client, allow: bool) -> Check {
        if let Some(peer) = &self.peer {
            let result = client
                .update_device(peer, &DevicePatch::default().allow_tunnel(allow))
                .await?;
            if !result.requested_fields_match {
                return Err("The target authorization did not match.".into());
            }
        } else if allow {
            return Err("Register the single isolated peer before granting access.".into());
        }
        Ok(())
    }

    async fn restore(&self, client: &Client) -> Check<Value> {
        let before = client.folder(&self.folder).await?;
        if before.id != self.folder || ![INITIAL, CHANGED].contains(&before.label.as_str()) {
            return Err("The target label is outside the two prepared test values.".into());
        }
        if before.label == CHANGED {
            client
                .update_folder(&self.folder, &FolderPatch::default().label(INITIAL))
                .await?;
        }
        self.grant(client, false).await?;
        let mut receipt = self.observe(client).await?;
        receipt["gateway_change_seen_before_restore"] = json!(before.label == CHANGED);
        Ok(receipt)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Setup {
    synthetic_target_key: String,
}

async fn run(
    engine: &Path,
    root: &Path,
    run: &str,
    gui: u16,
    data: SocketAddr,
    auxiliary: u16,
) -> Check {
    if root.canonicalize()? != root
        || !root
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(|name| name.starts_with("r33-gateway-target-"))
        || root.join("state").exists()
    {
        return Err("Use a new isolated target directory.".into());
    }
    let Some(init): Option<Setup> = take()? else {
        return Ok(());
    };
    let key = ApiKey::new(&init.synthetic_target_key)?;
    let program = LocalProgram::new(engine.to_path_buf())?.expected_sha256(ENGINE_HASH);
    let endpoint = ManagementEndpoint::http(&format!("http://127.0.0.1:{gui}/"))?;
    let settings = ManagedOptions::new(program, root.join("state"), endpoint)?
        .startup_timeout(Duration::from_secs(20))?
        .management_request_timeout(Duration::from_secs(8))?;
    let mut core = ManagedInstance::start(settings)
        .await
        .map_err(|error| format!("start the private core: {error:?}"))?;
    let outcome: Check = async {
        pin(&mut core, data, auxiliary)
            .await
            .map_err(|error| format!("prepare the data listener: {error:?}"))?;
        let rotation = core
            .rotate_api_key(key, Duration::from_secs(8))
            .await
            .map_err(|error| format!("rotate the synthetic target key: {error:?}"))?;
        if !(rotation.requested_key_matches && rotation.previous_key_rejected) {
            return Err("The synthetic target key did not replace the test instance key.".into());
        }
        let client = core.client();
        let mut witness = Target::create(root, client, run)
            .await
            .map_err(|error| format!("create the owned folder: {error:?}"))?;
        print(json!({"event":"owned-target-ready","ok":true,
                     "internal_device_id":client.instance().device_id.as_str(),
                     "engine":BASELINE_ENGINE_VERSION,"peer_configured":false,
                     "private_gui_port":gui,"native_p2p":data.to_string(),
                     "observation":witness.observe(client).await? }))?;
        let mut allowed = false;
        let work: Check =
            async {
                while let Some(command) = take()? {
                    let result = match command {
                        Command::Register { peer } => match DeviceId::parse(&peer) {
                            Ok(peer) => witness.register(client, peer).await,
                            Err(error) => Err(error.into()),
                        },
                        Command::Allow if !allowed => match witness.grant(client, true).await {
                            Ok(()) => {
                                allowed = true;
                                witness.observe(client).await
                            }
                            Err(error) => Err(error),
                        },
                        Command::Allow => Err("The scope has already used its one grant.".into()),
                        Command::State => witness.observe(client).await,
                        Command::Restore => witness.restore(client).await,
                        Command::End => break,
                    };
                    print(result.unwrap_or_else(
                        |_| json!({"ok":false,"state":"target-request-unconfirmed"}),
                    ))?;
                }
                Ok(())
            }
            .await;
        let last = witness.restore(client).await;
        print(json!({"event":"owned-target-final-readback","observation":last?}))?;
        work
    }
    .await;
    let stopped = core
        .shutdown(Duration::from_secs(14))
        .await
        .map_err(|error| format!("end the owned target after {outcome:?}: {error:?}"))?;
    print(
        json!({"event":"owned-target-exit","normal":stopped.code==Some(0)
            && stopped.tree_stopped && stopped.state_released && !stopped.forced}),
    )?;
    outcome
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let applied: Check = async {
        let [scope, engine, root, run_id, gui, data, auxiliary] = args.as_slice() else {
            return Err("Use the prepared target invocation.".into());
        };
        if run_id.len() != 32
            || !run_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || scope != "sealed-loopback-control"
        {
            return Err("Use the sealed synthetic target scope.".into());
        }
        let gui = fixture_port(gui)?;
        let data = fixture_port(data)?;
        let auxiliary = fixture_port(auxiliary)?;
        if gui == data || auxiliary == gui || auxiliary == data {
            return Err("The fixture listeners must be distinct.".into());
        }
        run(
            Path::new(engine),
            Path::new(root),
            run_id,
            gui,
            SocketAddr::from(([127, 0, 0, 1], data)),
            auxiliary,
        )
        .await
    }
    .await;
    if let Err(error) = applied {
        eprintln!("The isolated target could not finish: {error}");
        std::process::exit(2);
    }
}
