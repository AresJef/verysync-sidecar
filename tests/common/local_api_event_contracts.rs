//! Separate index-buffer source and shared bounded stream semantics.
use super::*;
use verysync_sidecar::*;
fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}
fn status() -> Reply {
    Reply::json(serde_json::json!({"myID":ID,"startTime":"native-generation"}))
}
fn event(id: u64) -> serde_json::Value {
    serde_json::json!({"id":id,"globalID":id+100,"time":"2026-11-16T00:00:00Z","type":"future-index-kind","data":{"private":KEY},"future":KEY})
}
fn options(server: &ScriptedServer) -> verysync_sidecar::Result<LocalApiConnectOptions> {
    LocalApiConnectOptions::new(ManagementEndpoint::http(&server.base)?)
}

#[tokio::test]
async fn local_index_stream_keeps_source_consumed_cursor_payload_and_ordinary_debug_private(
) -> TestResult {
    for filtered in [false, true] {
        let server = ScriptedServer::start(vec![
            version(),
            status(),
            version(),
            status(),
            Reply::json(serde_json::json!([event(1)])),
            status(),
            status(),
            Reply::json(serde_json::json!([event(4)])),
            status(),
            Reply::json(serde_json::json!([event(2), event(4)])),
            status(),
        ])
        .await?;
        let client = LocalApiClient::connect(options(&server)?).await?;
        let selection = EventFilter::new([EventKind::Unknown("future-index-kind".into())])?;
        let settings = EventOptions::default()
            .poll_interval(Duration::from_millis(25))?
            .queue_capacity(1)?;
        let mut stream = if filtered {
            client
                .subscribe_filtered_index_events(selection.clone(), settings)
                .await?
        } else {
            client.subscribe_index_events(settings).await?
        };
        let expected = EventSource::LocalIndex(filtered.then_some(selection));
        assert_eq!(stream.cursor().source, expected);
        let item = tokio::time::timeout(Duration::from_secs(3), stream.next())
            .await?
            .ok_or("stream ended")??;
        let EventStreamItem::Event(event) = item else {
            return Err("actual event missing".into());
        };
        assert_eq!(event.cursor.last_id, 2);
        assert_eq!(event.cursor.source, expected);
        assert_eq!(event.global_id, Some(102));
        assert_eq!(event.data()["private"], KEY);
        assert_eq!(event.extra()["future"], KEY);
        assert_eq!(stream.cursor().last_id, 2);
        assert!(!format!("{stream:?} {event:?}").contains(KEY));
        let gap = tokio::time::timeout(Duration::from_secs(3), stream.next())
            .await?
            .ok_or("index stream ended before the gap")??;
        assert!(matches!(gap, EventStreamItem::Gap(gap)
            if gap.reason == EventGapReason::MissingEvents
                && gap.previous.last_id == 2
                && gap.resume_from.last_id == 3
                && gap.previous.source == expected && gap.resume_from.source == expected));
        assert_eq!(stream.cursor().last_id, 3);
        let next = tokio::time::timeout(Duration::from_secs(3), stream.next())
            .await?
            .ok_or("index stream ended before event 4")??;
        assert!(matches!(next, EventStreamItem::Event(event)
            if event.cursor.last_id == 4 && event.cursor.source == expected));
        assert_eq!(stream.cursor().last_id, 4);
        stream.close().await?;
        let requests = server.finish().await?;
        assert!(
            requests[4].starts_with("GET /prefix/rest/localapi/events?since=0&limit=1&timeout=0")
        );
        assert!(requests[9].contains("since=1&limit=256&timeout=0"));
        assert!(requests
            .iter()
            .all(|r| !r.to_ascii_lowercase().contains("x-api-key:")));
        assert_eq!(requests[4].contains("events=future-index-kind"), filtered);
    }
    Ok(())
}

#[tokio::test]
async fn local_index_initial_license_failure_is_not_retried_and_client_remains_readable(
) -> TestResult {
    let server = ScriptedServer::start(vec![
        version(),
        status(),
        version(),
        status(),
        Reply::json(serde_json::json!({"code":3001,"error":KEY})),
        status(),
    ])
    .await?;
    let client = LocalApiClient::connect(options(&server)?).await?;
    let error = client
        .subscribe_index_events(EventOptions::default())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::LicenseRequired { code: 3001, .. }));
    assert!(!format!("{error:?}").contains(KEY));
    assert_eq!(client.system_status().await?.device_id.as_str(), ID);
    let requests = server.finish().await?;
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.contains("/localapi/events?"))
            .count(),
        1
    );
    assert_eq!(requests.len(), 6);
    Ok(())
}

#[tokio::test]
async fn local_index_rejects_gui_or_another_filter_cursor_before_subscription_reads() -> TestResult
{
    let server = ScriptedServer::start(vec![version(), status()]).await?;
    let client = LocalApiClient::connect(options(&server)?).await?;
    let filter = EventFilter::new([EventKind::StateChanged])?;
    for source in [
        EventSource::Standard,
        EventSource::Disk,
        EventSource::Filtered(filter.clone()),
        EventSource::LocalIndex(Some(filter)),
    ] {
        let cursor = EventCursor {
            source,
            device_id: DeviceId::parse(ID)?,
            engine_started_at: Some("native-generation".into()),
            last_id: 1,
        };
        assert!(matches!(
            client
                .subscribe_index_events(EventOptions::default().resume_from(cursor)?)
                .await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    assert_eq!(server.finish().await?.len(), 2);
    Ok(())
}
