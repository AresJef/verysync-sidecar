# Preview and apply settings

Use a settings preview to show the values the device reports before asking
someone to submit a change. The preview reads settings for the selected folder
registrations or the management listener. It leaves both configuration and
files unchanged.

Call `Client::preview_settings_changes()` with the folder label, folder-level
pause setting or native listener fields you want to change. Include each folder
once. Place a listener change last, since it can interrupt management access.
The preview gives you the checked device, the current and proposed values, and
the fields that may affect your management connection. Show labels and native
addresses only in a trusted interface. Ordinary Debug hides private values.

Keep the preview while your application waits for approval. Then give that
preview to `Client::commit_settings_preview()`. The client checks the device,
engine version and selected values before sending the first write. It checks
again before each subsequent write and leaves other settings alone. If another
writer already changed a selected value, inspect the conflict and create a new
preview before asking for approval again.

```no_run
use verysync_sidecar::{Client, FolderId, FolderPatch, SettingsChange, SettingsFieldState};

# async fn apply_reviewed_preview(client: &Client, id: &FolderId, approved: bool) -> verysync_sidecar::Result<()> {
let patch = FolderPatch::default().label("Shared reports").paused(true);
let preview = client.preview_settings_changes(&[SettingsChange::Folder { id, patch: &patch }]).await?;
// Show preview.steps() in your application's trusted review interface here.
if approved {
    let result = client.commit_settings_preview(preview).await;
    for field in &result.steps[0].fields {
        if field.state == SettingsFieldState::Confirmed {
            // The current stored value matches this request.
        }
    }
}
# Ok(())
# }
```

Each step keeps the original submission evidence alongside the field results.
A device can acknowledge a request while one or more fields still differ.
`Confirmed` means the current field matches, `Different` means it currently
differs, and `Unknown` means the write was attempted and current readback is
unavailable. `Conflict` identifies a selected value that changed before the
write. Later steps are `NotExecuted` when an earlier step stops the sequence.
If a step was attempted but the result is uncertain, read the current settings
before requesting another change. Earlier writes are retained.

A listener step keeps its operation receipt. Use
`SettingsStepResult::observe_listener()` with a management endpoint, credentials
and HTTPS trust selected by your application. The original acknowledgement
stays in the result when readback later succeeds. Save the receipt privately
if you need to check it again. When your application must keep a checkpoint
from before a possible interruption, use the separate
`execute_gui_listener_change_persisted()` flow in the
[listener recovery guide](gui-listener.md).

Clones of one client share the library's write lock. Another client or the
native GUI can change a setting after the last read and before VerySync applies
the PATCH. Coordinate those writers when you need exclusive access. A matching
setting describes the observed device at that time. It cannot identify the
writer or prove that synchronization paused or that a new listener is reachable.

The [preview_control example](../../examples/preview_control.rs) shows one
preview in a single application process. Start it with `--help` for the
input format. To run it in your own package, copy it to `src/bin/preview_control.rs`
and depend on `verysync-sidecar`, `serde` with `derive`, `serde_json`, and `tokio`
with `macros` and `rt-multi-thread`. Enable `verysync-sidecar`'s default TLS
feature if you use HTTPS. Supply one JSON line using a private input stream. Its
`connection` contains `endpoint`, `api_key`, and `expected_device_id`, and can
include `ca_pem` for HTTPS. Include `folder` with `id` and at least one of
`label` or `paused`, or `listener` with the new native `bind` authority.
For a listener change you can give a separately trusted `readback` connection.
Inspect the redacted preview. Write `apply` on a second line to submit it, or
end the input to leave the settings as they are.
