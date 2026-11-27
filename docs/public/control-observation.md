# Watch a folder or wait for an owned exit

Use `Client::observe_folder` to watch one folder on a management connection. Supply an optional peer when you also need the completion percentage that VerySync reports for that peer. This watch reads the engine's index and event stream. It does not open files, scan the folder, start a transfer, or change settings.

The first snapshot is available from `watch.snapshot()`. It records when the reads began and when the identity checks finished. Folder status and peer completion come from separate native reads. They can describe different moments. The event subscription starts before these reads, so updates that arrive while the snapshot is being read can still reach the caller. An event's position identifies where reading can continue. It does not identify the exact moment represented by the snapshot or a server task. VerySync does not supply a task ID for this watch.

```rust,no_run
use std::time::Duration;
use verysync_sidecar::{Client, Error, EventOptions, FolderId, Result};

async fn watch_once(client: &Client, folder: &FolderId) -> Result<()> {
    let policy = EventOptions::default().queue_capacity(8)?;
    let mut watch = client.observe_folder(folder, None, policy).await?;
    match watch.next_within(Duration::from_secs(2)).await {
        Ok(Some(update)) => {
            // Handle the update and check its refresh result before using the snapshot.
            let _ = (&update.item, &update.refresh, watch.snapshot());
            // Save watch.position() only after handling the update.
        }
        Ok(None) | Err(Error::Timeout { .. }) => {}
        Err(error) => return Err(error),
    }
    watch.close().await?;
    Ok(())
}
```

## Read gaps and continue from a saved position

The queue is bounded. A slow reader can cause gaps in the engine's available history. The watch delivers the gap explicitly and rereads only its selected folder and optional peer. An update identified as belonging to another folder can advance the shared stream position without reading that folder. If a refresh fails, the update still arrives and the last successful snapshot stays available. A later successful refresh gives you current state. The gap still describes history you did not see. If VerySync reports a
different start time while you handle an older event, the watch delivers that
event with a failed refresh. The stream's later restart gap marks when it began
reporting the new engine's state.

Save `FolderObservationPosition` in a private location after you handle an update. It supports Serde and contains the selected folder, optional peer, and consumed event cursor. It carries no endpoint or credential. At restart, reconnect with the intended address, trust settings, and fresh credentials, then pass that position to `Client::resume_folder_observation` with a new event policy. Resume checks the stored source and device against the connection. The first notice explains why the history since the saved position remains uncertain.

Use `next_within` to give one wait a deadline. If it times out while handling a pending update, the delivered position stays put. Call `next_within` again to continue that update, or `close` to end reads from this watch. Closing or dropping the watch leaves the program and any existing synchronization work running. If you close before handling a buffered update, save the last delivered position.

The `observe_control` example opens a watch, waits for one update and saves a position. Run `cargo run --example observe_control -- --help` for both forms. Give each run a new position file in a directory you control. Send the host's private JSON on standard input to keep the API key out of command-line arguments. A second process can continue with the saved position and newly supplied credentials.

## Observe an owned process exit

Call `ManagedInstance::control_generation` before waiting. Pass that marker and a deadline to `ManagedInstance::observe_control_exit`. If the wait returns `TimedOut`, keep the result as a record of what was known at that time. Wait again with the same marker. An `Exited` outcome contains the program's exit report, including its normal or forced exit and cleanup. A different generation is rejected before waiting.

The wait sends no shutdown or termination command. To shut down intentionally, use the owning handle's explicit lifecycle methods. A borrowed management connection can observe logical device identity. It cannot confirm an owned generation's exit.
