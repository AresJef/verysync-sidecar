//! Source-bound native Local-API index transport for the shared stream worker.
use super::{control::checked_control_response, LocalApiClient};
use crate::{Error, EventSource, RawMethod, RawRequest, RequestEffect, ResponseDiagnostic, Result};

impl LocalApiClient {
    pub(crate) async fn index_event_wire(
        &self,
        source: &EventSource,
        since: u64,
        limit: usize,
    ) -> Result<Vec<crate::events::WireEvent>> {
        let EventSource::LocalIndex(filter) = source else {
            return Err(Error::InvalidConfiguration {
                reason: "index-event request belongs to another native event source",
            });
        };
        let mut request = RawRequest::new(RawMethod::Get, ["events"], RequestEffect::ReadOnly)?
            .query("since", since.to_string())
            .query("limit", limit.to_string())
            .query("timeout", "0");
        if let Some(filter) = filter {
            request = request.query("events", filter.query_value());
        }
        // Shared stream head/batch checks identity and generation around reads.
        // This primitive preserves the distinct native code3001 classification.
        let response = checked_control_response(
            "read Local-API index events",
            self.send_raw(request).await?,
            false,
        )?;
        let invalid = || Error::InvalidResponse {
            operation: "read bounded ordered Local-API index events",
            response: ResponseDiagnostic::new(response.status, response.body.clone()),
        };
        let events: Vec<crate::events::WireEvent> =
            serde_json::from_slice(&response.body).map_err(|_| invalid())?;
        if !crate::events::validate_wire(&events, limit) {
            return Err(invalid());
        }
        Ok(events)
    }
}
