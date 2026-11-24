use crate::Stage;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use verysync_sidecar::{
    Client, CreateLocalSyncJob, LocalSyncCalendarRule, LocalSyncJob, LocalSyncJobPatch,
    LocalSyncMode, LocalSyncOperationControl, LocalSyncSchedule, StorageEndpoint, TargetPath,
};

const CASE_DIRECTORY: &str = "local-sync-cases";
const SAFETY_DIRECTORY: &str = "owned-schedule-state";
pub(crate) const GRANT_REVOKED: &str = "local-grant-revoked";
const INTERVAL: u32 = 60;
const SAMPLE: &str = "sample.txt";
const SENTINEL: &[u8] = b"R33 unrelated local sync sentinel\n";

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Trigger {
    Watch,
    Interval,
    Calendar,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Step {
    Prepare,
    Seed,
    Observe,
    Finish,
}

impl Trigger {
    const fn label(self) -> &'static str {
        match self {
            Self::Watch => "watch",
            Self::Interval => "interval",
            Self::Calendar => "calendar",
        }
    }
}

struct Plan {
    trigger: Trigger,
    earliest: Option<u64>,
    calendar: Option<(u8, String)>,
}

impl Plan {
    fn new(trigger: Trigger, now_ms: u64) -> Self {
        match trigger {
            Trigger::Calendar => {
                let (timestamp, weekday, time) = next_utc_calendar(now_ms / 1000);
                Self {
                    trigger,
                    earliest: Some(timestamp * 1000),
                    calendar: Some((weekday, time)),
                }
            }
            Trigger::Interval => Self {
                trigger,
                earliest: None,
                calendar: None,
            },
            Trigger::Watch => Self {
                trigger,
                earliest: None,
                calendar: None,
            },
        }
    }

    fn config(&self) -> Stage<LocalSyncSchedule> {
        match self.trigger {
            Trigger::Watch => Ok(LocalSyncSchedule::off()),
            Trigger::Interval => {
                LocalSyncSchedule::interval(INTERVAL).map_err(|_| "schedule-interval-invalid")
            }
            Trigger::Calendar => {
                let (weekday, clock) = self.calendar.as_ref().ok_or("calendar-rule-unavailable")?;
                let rule = LocalSyncCalendarRule::new(vec![*weekday], vec![clock.clone()])
                    .map_err(|_| "calendar-rule-invalid")?;
                LocalSyncSchedule::calendar(vec![rule], "UTC").map_err(|_| "calendar-tz-invalid")
            }
        }
    }

    fn matches(&self, job: &LocalSyncJob, enabled: bool) -> bool {
        if job.enabled != enabled || job.sync_on_startup || job.delete_extraneous {
            return false;
        }
        if job.watch_changes != Some(matches!(self.trigger, Trigger::Watch)) {
            return false;
        }
        match self.trigger {
            Trigger::Watch => {
                job.schedule_mode.as_deref() == Some("off")
                    && job.watch_check_interval_min == Some(0)
            }
            Trigger::Interval => {
                job.schedule_mode.as_deref() == Some("interval")
                    && job.schedule_interval_sec == Some(u64::from(INTERVAL))
            }
            Trigger::Calendar => {
                let Some((weekday, time)) = &self.calendar else {
                    return false;
                };
                job.schedule_mode.as_deref() == Some("calendar")
                    && job.schedule_timezone.as_deref() == Some("UTC")
                    && job.schedule_calendar.as_ref().is_some_and(|rules| {
                        rules.len() == 1
                            && rules[0].weekdays == [*weekday]
                            && rules[0].times.as_slice() == [time.as_str()]
                    })
            }
        }
    }

    fn report(&self) -> Value {
        json!({
            "trigger": self.trigger.label(),
            "earliest_expected_unix_millis": self.earliest,
            "interval_seconds": matches!(self.trigger, Trigger::Interval).then_some(INTERVAL),
            "calendar": self.calendar.as_ref().map(|(weekday,time)| json!({
                "timezone":"UTC", "weekday":weekday,"time":time,
                "unix_seconds":self.earliest.map(|ms| ms/1000)
            }))
        })
    }
}

fn next_utc_calendar(now: u64) -> (u64, u8, String) {
    let at = (now / 60 + 3) * 60;
    let weekday = ((at / 86_400 + 3) % 7) as u8 + 1;
    let hour = (at / 3600) % 24;
    let minute = (at / 60) % 60;
    (at, weekday, format!("{hour:02}:{minute:02}"))
}

fn wall_ms() -> Stage<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "schedule-clock-unavailable")?;
    u64::try_from(duration.as_millis()).map_err(|_| "schedule-clock-unavailable")
}

fn create_file(path: &Path, bytes: &[u8]) -> Stage<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "owned-case-file-create-failed")?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "owned-case-file-write-failed")
}

fn file_evidence(path: &Path) -> Stage<Option<Value>> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.is_file() || meta.len() > 1024 {
                return Err("unexpected-owned-case-file");
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("owned-case-file-stat-failed"),
    }
    let data = fs::read(path).map_err(|_| "owned-case-file-read-failed")?;
    Ok(Some(json!({
        "bytes": data.len(), "sha256": format!("{:x}",Sha256::digest(&data))
    })))
}

pub(crate) fn check_authorization(revoked: &Path) -> Stage<()> {
    match fs::symlink_metadata(revoked) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        _ => Err("local-schedule-grant-unavailable"),
    }
}

fn valid_case_name(name: &str) -> bool {
    ["watch-", "interval-", "calendar-"].iter().any(|prefix| {
        name.strip_prefix(prefix).is_some_and(|id| {
            (16..=32).contains(&id.len()) && id.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
    })
}

fn sentinel_same(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.len() == SENTINEL.len() as u64)
        && fs::read(path).is_ok_and(|data| data == SENTINEL)
}

struct Pair {
    source: PathBuf,
    target: PathBuf,
}

impl Pair {
    fn new(root: &Path, side: &str) -> Self {
        Self {
            source: root.join(side).join("source"),
            target: root.join(side).join("target"),
        }
    }

    fn create(&self) -> Stage<()> {
        fs::create_dir_all(&self.source).map_err(|_| "schedule-source-create-failed")?;
        fs::create_dir_all(&self.target).map_err(|_| "schedule-target-create-failed")?;
        create_file(&self.target.join("preserve.txt"), SENTINEL)
    }

    fn contains(&self, job: &LocalSyncJob) -> bool {
        let is_local = |endpoint: &StorageEndpoint, path: &Path| {
            serde_json::to_value(endpoint).is_ok_and(|fields| {
                fields["fsType"] == "basic" && fields["uri"].as_str() == path.to_str()
            })
        };
        is_local(&job.side_a, &self.source) && is_local(&job.side_b, &self.target)
    }
}

struct Case {
    root: PathBuf,
    marker: PathBuf,
    revoked: PathBuf,
    plan: Plan,
    treatment: Pair,
    control: Pair,
    enabled_at: Option<u64>,
    seeded_at: Option<u64>,
    last_absent: Option<u64>,
    first_present: Option<u64>,
    absence_before_expected: Option<u64>,
}

impl Case {
    fn new(root: PathBuf, marker: PathBuf, revoked: PathBuf, trigger: Trigger, now: u64) -> Self {
        let plan = Plan::new(trigger, now);
        Self {
            plan,
            treatment: Pair::new(&root, "active"),
            control: Pair::new(&root, "disabled"),
            root,
            marker,
            revoked,
            enabled_at: None,
            seeded_at: None,
            last_absent: None,
            first_present: None,
            absence_before_expected: None,
        }
    }

    fn job_label(&self, side: &str) -> Stage<String> {
        let name = self
            .root
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("schedule-case-name-invalid")?;
        Ok(format!("r33-{name}-{side}"))
    }

    async fn exact_job(&self, client: &Client, pair: &Pair, side: &str) -> Stage<LocalSyncJob> {
        let expected = self.job_label(side)?;
        let mut jobs = client
            .local_sync_jobs()
            .await
            .map_err(|_| "schedule-list-unavailable")?
            .into_iter()
            .filter(|job| job.label == expected);
        let job = jobs.next().ok_or("schedule-expected-job-missing")?;
        if jobs.next().is_some() || !pair.contains(&job) {
            return Err("schedule-job-ownership-mismatch");
        }
        Ok(job)
    }

    async fn register(&self, client: &Client, pair: &Pair, side: &str) -> Stage<(bool, bool)> {
        let source = StorageEndpoint::local(TargetPath::local(&pair.source))
            .map_err(|_| "schedule-source-invalid")?;
        let target = StorageEndpoint::local(TargetPath::local(&pair.target))
            .map_err(|_| "schedule-target-invalid")?;
        let requested = CreateLocalSyncJob::new(
            self.job_label(side)?,
            source,
            target,
            LocalSyncMode::MirrorAToB,
        )
        .map_err(|_| "schedule-job-config-invalid")?
        .enabled(false)
        .watch_changes(matches!(self.plan.trigger, Trigger::Watch), 0)
        .map_err(|_| "schedule-watch-setting-invalid")?
        .schedule(self.plan.config()?);
        check_authorization(&self.revoked)?;
        let response = client.create_local_sync_job(&requested).await;
        let observed = self.exact_job(client, pair, side).await?;
        Ok((response.is_ok(), self.plan.matches(&observed, false)))
    }

    async fn prepare(&mut self, client: &Client) -> Stage<Value> {
        check_authorization(&self.revoked)?;
        fs::create_dir(&self.root).map_err(|_| "schedule-case-exists")?;
        // Kept until exact owned registrations are absent, including on failure.
        create_file(&self.marker, b"owned case prepared\n")?;
        self.treatment.create()?;
        self.control.create()?;
        create_file(&self.root.join("outside.txt"), SENTINEL)?;
        let (active_ack, active) = self.register(client, &self.treatment, "active").await?;
        let (disabled_ack, disabled) = self.register(client, &self.control, "disabled").await?;
        if !active || !disabled {
            return Ok(json!({
                "ok": false, "code":"schedule-request-not-observed",
                "prepared_job_matches":active,"disabled_job_matches":disabled,
                "initial_create_acknowledgements":[active_ack,disabled_ack],
                "armed":false,"schedule":self.plan.report()
            }));
        }
        let job = self.exact_job(client, &self.treatment, "active").await?;
        let requested_at = wall_ms()?;
        let requested = LocalSyncJobPatch::default().enabled(true);
        check_authorization(&self.revoked)?;
        let acknowledgement = client.update_local_sync_job(&job.job_id, &requested).await;
        let after = self.exact_job(client, &self.treatment, "active").await?;
        let matched = self.plan.matches(&after, true) && after.job_id == job.job_id;
        if matched {
            self.enabled_at = Some(requested_at);
            if matches!(self.plan.trigger, Trigger::Interval) {
                self.plan.earliest = Some(requested_at + u64::from(INTERVAL) * 1000);
            }
        }
        Ok(json!({
            "ok":matched, "armed":matched, "schedule":self.plan.report(),
            "enabled_request_at_unix_millis":requested_at,
            "enable_acknowledged":acknowledgement.is_ok_and(|value| value.requested_fields_match),
            "disabled_control_readback":disabled,
            "initial_create_acknowledgements":[active_ack,disabled_ack]
        }))
    }

    fn seed(&mut self) -> Stage<Value> {
        check_authorization(&self.revoked)?;
        if self.enabled_at.is_none() || self.seeded_at.is_some() {
            return Err("schedule-seed-not-available");
        }
        let now = wall_ms()?;
        if self.plan.earliest.is_some_and(|at| now + 3000 >= at)
            || file_evidence(&self.treatment.target.join(SAMPLE))?.is_some()
            || file_evidence(&self.control.target.join(SAMPLE))?.is_some()
        {
            return Err("schedule-seed-has-no-valid-pre-trigger-window");
        }
        let payload = format!("R33 VS-041-W {}\n", self.job_label("sample")?);
        create_file(&self.control.source.join(SAMPLE), payload.as_bytes())?;
        check_authorization(&self.revoked)?;
        create_file(&self.treatment.source.join(SAMPLE), payload.as_bytes())?;
        self.seeded_at = Some(wall_ms()?);
        Ok(json!({
            "ok":true,"seeded_at_unix_millis":self.seeded_at,
            "target_absent_before_seed":true,
            "source":file_evidence(&self.treatment.source.join(SAMPLE))?,
            "control_source":file_evidence(&self.control.source.join(SAMPLE))?
        }))
    }

    async fn observe(&mut self, client: &Client) -> Stage<Value> {
        let active = self.exact_job(client, &self.treatment, "active").await?;
        let control = self.exact_job(client, &self.control, "disabled").await?;
        let status = client.local_sync_status(&active.job_id).await.ok();
        let now = wall_ms()?;
        let source = file_evidence(&self.treatment.source.join(SAMPLE))?;
        let destination = file_evidence(&self.treatment.target.join(SAMPLE))?;
        let control_source = file_evidence(&self.control.source.join(SAMPLE))?;
        let control_destination = file_evidence(&self.control.target.join(SAMPLE))?;
        if destination.is_none() && self.first_present.is_none() {
            self.last_absent = Some(now);
            if self.plan.earliest.is_some_and(|at| now < at) {
                self.absence_before_expected = Some(now);
            }
        } else if destination.is_some() && self.first_present.is_none() {
            self.first_present = Some(now);
        }

        let retained = sentinel_same(&self.root.join("outside.txt"))
            && sentinel_same(&self.treatment.target.join("preserve.txt"))
            && sentinel_same(&self.control.target.join("preserve.txt"));
        let configured = self.plan.matches(&active, true) && self.plan.matches(&control, false);
        let floor = matches!(self.plan.trigger, Trigger::Interval)
            .then_some(2000)
            .unwrap_or(0);
        let in_time = match (self.seeded_at, self.first_present, self.plan.earliest) {
            (Some(seed), Some(first), None) => first >= seed,
            (Some(seed), Some(first), Some(at)) => {
                first >= seed
                    && first >= at.saturating_sub(floor)
                    && self
                        .absence_before_expected
                        .is_some_and(|observed| observed >= seed)
            }
            _ => false,
        };
        let completed = if destination.is_some() {
            client
                .local_sync_run(&active.job_id)
                .await
                .ok()
                .filter(|run| {
                    run.job_id == active.job_id
                        && !run.finished.starts_with("0001-")
                        && !run.finished.is_empty()
                        && run.summary.completed > 0
                        && run.summary.failed == 0
                        && run.cancelled != Some(true)
                        && run.error.as_ref().is_none_or(String::is_empty)
                })
        } else {
            None
        };
        let effect = source.is_some()
            && destination == source
            && control_source == source
            && control_destination.is_none()
            && retained
            && configured
            && in_time
            && status
                .as_ref()
                .is_some_and(|item| item.operation_id.is_some())
            && completed.is_some();

        Ok(json!({
            "ok":true,"schedule":self.plan.report(),"snapshot_at_unix_millis":now,
            "seeded_at_unix_millis":self.seeded_at, "last_absent_unix_millis":self.last_absent,
            "last_pre_due_absence_unix_millis":self.absence_before_expected,
            "first_presence_unix_millis":self.first_present,
            "actual_active_config_matches":self.plan.matches(&active,true),
            "actual_disabled_config_matches":self.plan.matches(&control,false),
            "native_mode":active.schedule_mode,
            "native_completed_run":completed.map(|run| json!({
                "started":run.started,"finished":run.finished,"copies":run.summary.completed
            })),
            "native_watch":active.watch_changes,
            "native_operation_seen":status.as_ref().is_some_and(|item| item.operation_id.is_some()),
            "native_run_has_error":status.is_some_and(|item| item.last_error.is_some_and(|s|!s.is_empty())),
            "source":source,"destination":destination,"control_source":control_source,
            "control_destination":control_destination,"sentinels_retained":retained,
            "file_effect_correlated":effect
        }))
    }
}

pub(crate) struct Scheduler {
    directory: PathBuf,
    safety: PathBuf,
    revoked: PathBuf,
    active: Option<Case>,
}

impl Scheduler {
    pub(crate) fn new(root: &Path) -> Self {
        Self {
            directory: root.join(CASE_DIRECTORY),
            safety: root.join(SAFETY_DIRECTORY),
            revoked: root.join(GRANT_REVOKED),
            active: None,
        }
    }

    pub(crate) async fn run(
        &mut self,
        client: &Client,
        trigger: Trigger,
        step: Step,
        request: &str,
    ) -> Stage<Value> {
        match step {
            Step::Prepare => {
                check_authorization(&self.revoked)?;
                if self.active.is_some() {
                    return Err("finish-current-owned-schedule-case-first");
                }
                fs::create_dir_all(&self.directory).map_err(|_| "schedule-root-create-failed")?;
                fs::create_dir_all(&self.safety)
                    .map_err(|_| "schedule-safety-root-create-failed")?;
                let name = format!("{}-{request}", trigger.label());
                if !valid_case_name(&name) {
                    return Err("schedule-case-name-invalid");
                }
                let mut case = Case::new(
                    self.directory.join(&name),
                    self.safety.join(name),
                    self.revoked.clone(),
                    trigger,
                    wall_ms()?,
                );
                let result = case.prepare(client).await;
                self.active = Some(case);
                result
            }
            Step::Seed => self.case_mut(trigger)?.seed(),
            Step::Observe => self.case_mut(trigger)?.observe(client).await,
            Step::Finish => {
                let case = self.case_mut(trigger)?;
                let original = case.observe(client).await;
                Self::remove_owned(client, &case.root, &case.marker).await?;
                let original = match original {
                    Ok(observation) => observation,
                    Err(code) => {
                        self.active = None;
                        return Ok(json!({"ok":false,"code":code,"registrations_absent":true}));
                    }
                };
                let case = self.case_mut(trigger)?;
                let same = file_evidence(&case.treatment.source.join(SAMPLE))?
                    == original["source"]
                        .as_object()
                        .map(|value| Value::Object(value.clone()))
                    && file_evidence(&case.treatment.target.join(SAMPLE))?
                        == original["destination"]
                            .as_object()
                            .map(|value| Value::Object(value.clone()))
                    && file_evidence(&case.control.source.join(SAMPLE))?
                        == original["control_source"]
                            .as_object()
                            .map(|value| Value::Object(value.clone()))
                    && file_evidence(&case.control.target.join(SAMPLE))?.is_none()
                    && sentinel_same(&case.root.join("outside.txt"))
                    && sentinel_same(&case.treatment.target.join("preserve.txt"))
                    && sentinel_same(&case.control.target.join("preserve.txt"));
                self.active = None;
                Ok(
                    json!({"ok":same,"registrations_absent":true,"files_preserved":same,"final":original}),
                )
            }
        }
    }

    fn case_mut(&mut self, trigger: Trigger) -> Stage<&mut Case> {
        self.active
            .as_mut()
            .filter(|case| case.plan.trigger == trigger)
            .ok_or("requested-schedule-case-is-not-active")
    }

    async fn remove_owned(client: &Client, root: &Path, marker: &Path) -> Stage<()> {
        match fs::symlink_metadata(marker) {
            Ok(found) if found.is_file() => (),
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            _ => return Err("schedule-safety-marker-invalid"),
        }
        let name = root
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("schedule-case-name-invalid")?;
        let active = format!("r33-{name}-active");
        let disabled = format!("r33-{name}-disabled");
        let jobs = client
            .local_sync_jobs()
            .await
            .map_err(|_| "schedule-cleanup-list-failed")?;
        let mut selected = Vec::new();
        for job in jobs {
            let side = if job.label == active {
                "active"
            } else if job.label == disabled {
                "disabled"
            } else {
                continue;
            };
            if selected.iter().any(|(other, _)| other == &side)
                || !Pair::new(root, side).contains(&job)
            {
                return Err("schedule-cleanup-ownership-mismatch");
            }
            selected.push((side, job));
        }
        for (_, job) in selected {
            if job.enabled {
                let _ = client
                    .update_local_sync_job(
                        &job.job_id,
                        &LocalSyncJobPatch::default().enabled(false),
                    )
                    .await;
                if client
                    .local_sync_job(&job.job_id)
                    .await
                    .map_or(true, |live| live.enabled)
                {
                    return Err("schedule-cleanup-registration-still-enabled");
                }
            }
            let status = client
                .local_sync_status(&job.job_id)
                .await
                .map_err(|_| "schedule-cleanup-operation-state-unavailable")?;
            if status.state != "idle" {
                let operation = status
                    .operation_id
                    .as_ref()
                    .ok_or("schedule-cleanup-operation-unknown")?;
                let _ = client
                    .control_local_sync_operation(
                        &job.job_id,
                        operation,
                        LocalSyncOperationControl::Stop,
                    )
                    .await;
                let mut idle = false;
                for _ in 0..5 {
                    if client
                        .local_sync_status(&job.job_id)
                        .await
                        .is_ok_and(|item| item.state == "idle")
                    {
                        idle = true;
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                if !idle {
                    return Err("schedule-cleanup-operation-still-active");
                }
            }
            let acknowledged = client.delete_local_sync_job(&job.job_id).await;
            let remaining = client
                .local_sync_jobs()
                .await
                .map_err(|_| "schedule-cleanup-readback-failed")?;
            if remaining.iter().any(|item| item.job_id == job.job_id) {
                return Err("schedule-cleanup-owned-registration-remains");
            }
            if acknowledged.is_err() && remaining.iter().any(|item| item.label == job.label) {
                return Err("schedule-cleanup-label-remains");
            }
        }
        fs::remove_file(marker).map_err(|_| "schedule-cleanup-marker-remains")
    }

    pub(crate) async fn cleanup(&mut self, client: &Client) -> Stage<()> {
        let markers = match fs::read_dir(&self.safety) {
            Ok(markers) => markers,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err("schedule-case-directory-unavailable"),
        };
        for entry in markers {
            let entry = entry.map_err(|_| "schedule-case-entry-unavailable")?;
            let name = entry.file_name();
            if !name.to_str().is_some_and(valid_case_name) {
                return Err("schedule-safety-marker-name-invalid");
            }
            Self::remove_owned(client, &self.directory.join(name), &entry.path()).await?;
        }
        self.active = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{check_authorization, next_utc_calendar, valid_case_name};

    #[test]
    fn cleanup_marker_names_cannot_point_outside_the_known_case() {
        assert!(valid_case_name("watch-0123456789abcdef"));
        assert!(!valid_case_name("watch-../0123456789abcdef"));
        assert!(!valid_case_name("marketing-0123456789abcdef"));
    }

    #[test]
    fn observed_revocation_refuses_new_work() {
        let root =
            std::env::temp_dir().join(format!("r33-schedule-signal-{}", super::wall_ms().unwrap()));
        std::fs::create_dir(&root).unwrap();
        let marker = root.join("revoked");
        assert_eq!(check_authorization(&marker), Ok(()));
        std::fs::write(&marker, b"").unwrap();
        assert_eq!(
            check_authorization(&marker),
            Err("local-schedule-grant-unavailable")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn calendar_uses_target_weekday_when_lead_crosses_midnight() {
        let sunday_2359 = 3 * 86_400 + 23 * 3600 + 59 * 60 + 50;
        assert_eq!(
            next_utc_calendar(sunday_2359),
            (4 * 86_400 + 2 * 60, 1, "00:02".to_owned())
        );
    }

    #[test]
    fn calendar_lead_is_at_least_two_minutes() {
        let now = 1_800_000_059;
        let (scheduled, _, _) = next_utc_calendar(now);
        assert!((120..=180).contains(&(scheduled - now)));
        assert_eq!(scheduled % 60, 0);
    }
}

#[cfg(test)]
mod native_control {
    use super::{Scheduler, Step, Trigger};
    use crate::{end, start, Stage};
    use serde_json::json;
    use std::{env, path::PathBuf};

    #[tokio::test]
    #[ignore = "uses one fixed native instance across two private process lifetimes"]
    async fn recovery_disarms_owned_scope_with_synthetic_files_read_only() {
        use super::{CASE_DIRECTORY, GRANT_REVOKED, SAFETY_DIRECTORY, SENTINEL};
        use std::fs;
        let root = PathBuf::from(env::var_os("R33_PRIVATE_CONTROL_DIR").unwrap());
        let program = PathBuf::from(env::var_os("R33_PINNED_ENGINE").unwrap());
        let phase = env::var("R33_RECOVERY_CONTROL_PHASE").unwrap();
        let id = "recoverycontrol1";
        let name = format!("watch-{id}");
        let data_root = root.join(CASE_DIRECTORY).join(&name);
        let marker = root.join(SAFETY_DIRECTORY).join(name);
        let mut core = start(program, &root).await.unwrap();
        let mut scheduler = Scheduler::new(&root);
        let observed: Stage<_> = async {
            if phase == "seed" {
                let result = scheduler
                    .run(core.client(), Trigger::Watch, Step::Prepare, id)
                    .await?;
                assert_eq!(result["armed"], false);
                let rows = core.client().local_sync_jobs().await.unwrap();
                assert_eq!(rows.len(), 2);
                assert!(rows.iter().all(|job| !job.enabled));
                assert!(marker.is_file());
                fs::write(root.join(GRANT_REVOKED), b"").unwrap();
                return Ok(
                    json!({"phase":"seed","case_registered":true,"metadata_persisted":true}),
                );
            }
            assert_eq!(phase, "recover");
            let forbidden = data_root
                .join("active")
                .join("target")
                .join("ungranted-write");
            assert!(fs::write(&forbidden, b"must be denied").is_err());
            let original = data_root.join("active").join("target").join("preserve.txt");
            assert_eq!(fs::read(&original).unwrap(), SENTINEL);
            let rows = core.client().local_sync_jobs().await.unwrap();
            assert_eq!(rows.len(), 2);
            assert!(marker.is_file());
            scheduler.cleanup(core.client()).await?;
            assert!(core.client().local_sync_jobs().await.unwrap().is_empty());
            assert!(!marker.exists());
            assert!(!forbidden.exists());
            assert_eq!(fs::read(original).unwrap(), SENTINEL);
            Ok(
                json!({"phase":"recover","readonly_case_data":true,"exact_rows_removed":true,
                     "outside_case_metadata_cleared":true,"expected_bytes_preserved":true}),
            )
        }
        .await;
        assert!(end(&mut core).await);
        println!("R33_SCHEDULE_RECOVERY {}", observed.unwrap());
    }

    #[tokio::test]
    #[ignore = "uses the exact isolated native core in a private test sandbox"]
    async fn unlicensed_normalization_never_arms_a_job_and_removes_owned_rows() {
        let root = PathBuf::from(env::var_os("R33_PRIVATE_CONTROL_DIR").unwrap());
        let program = PathBuf::from(env::var_os("R33_PINNED_ENGINE").unwrap());
        let mut core = start(program, &root).await.unwrap();
        let mut scheduler = Scheduler::new(&root);
        let result: Stage<Vec<_>> = async {
            let mut results = Vec::new();
            for (kind, id) in [
                (Trigger::Watch, "watchcontrol00001"),
                (Trigger::Interval, "intervalcontrol01"),
                (Trigger::Calendar, "calendarcontrol01"),
            ] {
                let report = scheduler
                    .run(core.client(), kind, Step::Prepare, id)
                    .await?;
                if report["armed"] != false || report["ok"] != false {
                    return Err("free-control-was-armed");
                }
                let jobs = core.client().local_sync_jobs().await.map_err(|_| "free-control-jobs-unavailable")?;
                if jobs.len()!=2 || jobs.iter().any(|job|job.enabled || job.sync_on_startup) {
                    return Err("free-control-registration-active");
                }
                let files = scheduler.run(core.client(),kind,Step::Observe,id).await?;
                scheduler.cleanup(core.client()).await?;
                if !core.client().local_sync_jobs().await.map_err(|_| "free-control-cleanup-unavailable")?.is_empty() {
                    return Err("free-control-owned-rows-remain");
                }
                results.push(json!({"prepare":report,"readback":files,"registrations_absent_after_cleanup":true}));
            }
            Ok(results)
        }.await;
        let _ = scheduler.cleanup(core.client()).await;
        let exited = end(&mut core).await;
        assert!(exited);
        println!(
            "R33_SCHEDULE_CONTROL {}",
            json!({
                "scope":"native unlicensed control",
                "cases":result.unwrap(),"normal_owned_exit":exited
            })
        );
    }
}
