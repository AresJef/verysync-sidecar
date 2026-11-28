//! One modifying request for an exact peer and independent readback.

use std::time::Duration;

use reqwest::Method;
use tokio::time::Instant;

use super::{device_control::patch_json, workflow_write_result, Client};
use crate::{
    CreateDeviceOptions, DeviceId, DevicePatch, DeviceWorkflowOutcome, DeviceWorkflowReport, Error,
    OperationOptions, OperationPhase, Result,
};

const CHANGE: &str = "apply the requested peer configuration";
const READ: &str = "check the selected peer configuration";
const PEER: &str = "observe the selected peer connection";

impl Client {
    /// Register one new remote peer and verify the requested fields. An ID
    /// already present before the request never counts as a new registration.
    pub async fn create_device_and_verify(
        &self,
        input: &CreateDeviceOptions,
        options: OperationOptions,
    ) -> Result<DeviceWorkflowReport> {
        self.device_workflow(&input.id, &input.patch, Some(input), None, options)
            .await
    }

    /// Apply a peer patch once, skipping a write if its fields already match.
    /// The original reply and current authenticated snapshot remain separate.
    pub async fn update_device_and_verify(
        &self,
        device: &DeviceId,
        patch: &DevicePatch,
        options: OperationOptions,
    ) -> Result<DeviceWorkflowReport> {
        self.device_workflow(device, patch, None, None, options)
            .await
    }

    /// Set the peer's pause flag and optionally wait for its live connected
    /// value. The two observations are reported independently. An absent
    /// connection entry is insufficient to confirm disconnection.
    pub async fn set_device_pause_and_verify(
        &self,
        device: &DeviceId,
        paused: bool,
        expected_connected: Option<bool>,
        options: OperationOptions,
    ) -> Result<DeviceWorkflowReport> {
        self.device_workflow(
            device,
            &DevicePatch::default().paused(paused),
            None,
            expected_connected,
            options,
        )
        .await
    }

    async fn device_workflow(
        &self,
        device: &DeviceId,
        patch: &DevicePatch,
        create: Option<&CreateDeviceOptions>,
        expected_connected: Option<bool>,
        options: OperationOptions,
    ) -> Result<DeviceWorkflowReport> {
        use DeviceWorkflowOutcome as Outcome;
        patch.validate(create.is_none())?;
        self.require_remote_device(device)?;
        let (method, url) = if create.is_some() {
            (
                Method::POST,
                self.connection.management_url("rest/config/devices", &[])?,
            )
        } else {
            (Method::PATCH, self.device_url(device)?)
        };
        let context = options.start()?;
        let dispatch = context.dispatch_deadline();
        let mut report = DeviceWorkflowReport {
            outcome: Outcome::NotSubmitted,
            write: Default::default(),
            original: None,
            observed: None,
            connection: None,
            expected_connection_observed: None,
            observation_error: None,
        };
        let mut guard = None;
        let attempt = context
            .wait(dispatch, CHANGE, async {
                context.phase(OperationPhase::Checking);
                guard = Some(self.connection.mutation_lock.lock().await);
                self.observe_control_identity().await?;
                let body = if let Some(create) = create {
                    self.prepare_device_creation(create).await?
                } else {
                    let current = self.device(device).await?;
                    patch.validate_advanced_readback(&current.extra)?;
                    if patch.matches(&current) {
                        self.system_status().await?;
                        report.observed = Some(current);
                        return Ok(false);
                    }
                    patch_json(patch)?
                };
                self.system_status().await?;
                if Instant::now() >= dispatch {
                    return Err(Error::Timeout { operation: CHANGE });
                }
                let request = self.connection.authorized_request(method, url, Some(&body));
                self.connection
                    .send_workflow_write(CHANGE, request, &context, &mut report.write)
                    .await?;
                Ok(true)
            })
            .await;
        if matches!(attempt, Ok(false)) {
            report.outcome = Outcome::AlreadyMatched;
        } else {
            report.original = Some(workflow_write_result(
                CHANGE,
                report.write,
                attempt.map(|_| ()),
            ));
            if report.write.response_complete
                && matches!(
                    report.original,
                    Some(Err(Error::Authentication { .. }
                        | Error::AccessDenied { .. }
                        | Error::LicenseRequired { .. }))
                )
            {
                report.outcome = Outcome::Rejected;
            } else if report.write.dispatched {
                context.phase(OperationPhase::Verifying);
                let observed = context
                    .wait(context.deadline, READ, async {
                        self.observe_control_identity().await?;
                        let current = match self.device(device).await {
                            Ok(current) => {
                                patch.validate_advanced_readback(&current.extra)?;
                                Some(current)
                            }
                            Err(Error::DeviceNotFound { .. }) => None,
                            Err(source) => return Err(source),
                        };
                        self.system_status().await?;
                        Ok(current)
                    })
                    .await;
                match observed {
                    Ok(current) => {
                        report.outcome = if current
                            .as_ref()
                            .is_some_and(|current| patch.matches(current))
                        {
                            Outcome::CurrentMatches
                        } else {
                            Outcome::CurrentDiffers
                        };
                        report.observed = current;
                    }
                    Err(source) => {
                        report.outcome = Outcome::Unconfirmed;
                        report.observation_error = Some(source);
                    }
                }
            }
        }
        drop(guard);
        if let Some(expected) = expected_connected.filter(|_| {
            matches!(
                report.outcome,
                Outcome::AlreadyMatched | Outcome::CurrentMatches
            )
        }) {
            report.expected_connection_observed = Some(false);
            context.phase(OperationPhase::Verifying);
            let observed = context
                .wait(context.deadline, PEER, async {
                    loop {
                        self.system_status().await?;
                        let mut snapshot = self.connections().await?;
                        let current = self.device(device).await?;
                        self.system_status().await?;
                        patch.validate_advanced_readback(&current.extra)?;
                        if !patch.matches(&current) {
                            report.outcome = Outcome::CurrentDiffers;
                            report.observed = Some(current);
                            report.connection = None;
                            return Err(Error::ConfigurationChanged);
                        }
                        report.connection = snapshot.connections.remove(device);
                        if report
                            .connection
                            .as_ref()
                            .is_some_and(|entry| entry.connected == expected)
                        {
                            return Ok(());
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                })
                .await;
            report.expected_connection_observed = Some(observed.is_ok());
            report.observation_error = observed.err();
        }
        context.phase(OperationPhase::Finished);
        Ok(report)
    }
}
