use super::*;

async fn one_queued(stream: &EventSubscription) -> TestResult {
    tokio::time::timeout(Duration::from_secs(3), async {
        while stream.buffered_items() != 1 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await?;
    Ok(())
}

async fn consumed_event(stream: &mut EventSubscription, id: u64) -> TestResult {
    assert!(matches!(
        next(stream).await?,
        EventStreamItem::Event(event) if event.cursor.last_id == id && event.cursor.source == stream.cursor().source
    ));
    assert_eq!(stream.cursor().last_id, id);
    Ok(())
}

async fn consumed_gap(stream: &mut EventSubscription, previous: u64, resume: u64) -> TestResult {
    let old = stream.cursor().clone();
    let EventStreamItem::Gap(gap) = next(stream).await? else {
        return Err("expected a MissingEvents notification before the following event".into());
    };
    assert_eq!(gap.reason, EventGapReason::MissingEvents);
    assert_eq!(gap.previous, old);
    assert_eq!(gap.previous.last_id, previous);
    assert_eq!(gap.resume_from.last_id, resume);
    assert_eq!(gap.resume_from.source, old.source);
    assert_eq!(gap.resume_from.device_id, old.device_id);
    assert_eq!(gap.resume_from.engine_started_at, old.engine_started_at);
    assert_eq!(stream.cursor(), &gap.resume_from);
    Ok(())
}

#[tokio::test]
async fn delivers_event_gap_event_with_the_consumed_cursor_and_resumes_from_the_gap() -> TestResult
{
    let server = Server::start().await?;
    let client = server.client().await?;
    let mut stream = client.subscribe_events(fast()?.queue_capacity(1)?).await?;
    let initial = stream.cursor().clone();
    assert_eq!(initial.last_id, 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(35), stream.next())
            .await
            .is_err()
    );
    assert_eq!(*stream.cursor(), initial);
    server.replace(vec![
        event(1, "StartupCompleted"),
        event(2, "ConfigSaved"),
        event(4, "ConfigSaved"),
    ]);

    one_queued(&stream).await?;
    assert_eq!(stream.cursor().last_id, 1);
    consumed_event(&mut stream, 2).await?;
    one_queued(&stream).await?;
    assert_eq!(stream.cursor().last_id, 2);
    consumed_gap(&mut stream, 2, 3).await?;
    let saved = stream.cursor().clone();
    one_queued(&stream).await?;
    assert_eq!(stream.cursor().last_id, 3);
    consumed_event(&mut stream, 4).await?;
    stream.close().await?;

    let mut resumed = client
        .subscribe_events(fast()?.queue_capacity(1)?.resume_from(saved)?)
        .await?;
    assert!(matches!(next(&mut resumed).await?,
        EventStreamItem::Gap(gap) if gap.reason == EventGapReason::ResumedContinuityUnverified));
    consumed_event(&mut resumed, 4).await?;
    server.state.failures_left.store(1, Ordering::SeqCst);
    assert!(matches!(next(&mut resumed).await?,
        EventStreamItem::Gap(gap) if gap.reason == EventGapReason::ConnectionInterrupted));
    assert!(matches!(
        next(&mut resumed).await?,
        EventStreamItem::Reconnected { .. }
    ));
    assert_eq!(resumed.cursor().last_id, 4);
    server.replace(vec![event(4, "ConfigSaved"), event(5, "ConfigSaved")]);
    consumed_event(&mut resumed, 5).await?;
    resumed.close().await?;
    server.finish().await?;
    println!("event evidence: observed=2,gap(2->3),4 consumed=2,3,4 queued=1,2,3 resumed_from=3 reconnected_from=4");
    Ok(())
}

#[tokio::test]
async fn reports_each_gap_of_a_bounded_tail_on_each_management_source() -> TestResult {
    for source in [
        EventSource::Standard,
        EventSource::Disk,
        EventSource::Filtered(EventFilter::new([EventKind::ConfigurationSaved])?),
    ] {
        let server = Server::start().await?;
        let client = server.client().await?;
        let supply = |ids: &[u64]| {
            let rows: Vec<_> = ids
                .iter()
                .map(|&id| {
                    let mut row = event(id, "ConfigSaved");
                    row["globalID"] = json!(id * 100);
                    row
                })
                .collect();
            match &source {
                EventSource::Standard => server.replace(rows),
                EventSource::Disk => *server.state.disk_events.lock().unwrap() = rows,
                EventSource::Filtered(_) => {
                    server
                        .state
                        .filtered_events
                        .lock()
                        .unwrap()
                        .insert("ConfigSaved".into(), rows);
                }
                _ => unreachable!(),
            }
        };
        supply(&[1]);
        let options = fast()?.queue_capacity(1)?.batch_limit(3)?;
        let mut stream = match &source {
            EventSource::Standard => client.subscribe_events(options).await?,
            EventSource::Disk => client.subscribe_disk_events(options).await?,
            EventSource::Filtered(filter) => {
                client
                    .subscribe_filtered_events(filter.clone(), options)
                    .await?
            }
            _ => unreachable!(),
        };
        assert_eq!(stream.cursor().source, source);
        assert_eq!(stream.cursor().last_id, 1);
        supply(&[1, 2, 3, 5, 8]);
        consumed_gap(&mut stream, 1, 2).await?;
        consumed_event(&mut stream, 3).await?;
        consumed_gap(&mut stream, 3, 4).await?;
        consumed_event(&mut stream, 5).await?;
        consumed_gap(&mut stream, 5, 7).await?;
        consumed_event(&mut stream, 8).await?;
        supply(&[8, 9, 10]);
        consumed_event(&mut stream, 9).await?;
        consumed_event(&mut stream, 10).await?;
        supply(&[10, 12]);
        one_queued(&stream).await?;
        assert_eq!(stream.cursor().last_id, 10);
        tokio::time::timeout(Duration::from_secs(3), stream.close()).await??;
        server.finish().await?;
        println!("event evidence: source={source:?} bounded_tail=true interior_gaps=2 global_id_independent=true closed_with_unconsumed_work=true");
    }
    Ok(())
}

#[tokio::test]
async fn a_duplicate_source_id_rejects_the_batch_without_advancing() -> TestResult {
    let server = Server::start().await?;
    let client = server.client().await?;
    let mut stream = client.subscribe_events(fast()?.queue_capacity(1)?).await?;
    let original = stream.cursor().clone();
    server.replace(vec![
        event(1, "StartupCompleted"),
        event(3, "ConfigSaved"),
        event(3, "StateChanged"),
    ]);
    let failure = tokio::time::timeout(Duration::from_secs(3), stream.next())
        .await?
        .ok_or("missing duplicate-ID response error")?;
    assert!(matches!(failure, Err(Error::InvalidResponse { .. })));
    assert_eq!(stream.cursor(), &original);
    assert!(stream.next().await.is_none());
    stream.close().await?;
    server.finish().await?;
    Ok(())
}
