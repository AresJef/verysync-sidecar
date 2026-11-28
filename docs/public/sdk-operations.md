# SDK operations

Choose the operation that matches the result your application needs. Use the
linked guides for prerequisites, Rust examples, native limits, and recovery
steps. The managed instance and its official VerySync program continue to own
process, scan, synchronization and storage activity.

For a method that returns an operation report, check its completion and
original request separately. A reply may be lost even when a later read
confirms the requested state. If the effect is unconfirmed, inspect the same
instance and selected files before submitting another change. Use
`OperationOptions` for an explicit total timeout and optional progress.
After dispatch, native work can continue if you stop waiting. Read the report
to check which request was sent.

| ID | Goal and Rust entry | What the result establishes |
| --- | --- | --- |
| 01 | [Upgrade the owned program](program-upgrades.md) using `install_kernel_upgrade` or `upgrade_kernel_and_wait_ready`. | Check the installed artifact and running readiness separately. A lost reply may allow a read-only disk check on the original instance. |
| 02 | [Prepare a selected program](program-preparation.md) with `prepare` or `resolve` from the program source or cache. | Check the program source, target architecture, version, and available integrity evidence. A trusted cache entry can be used offline. |
| 03 | [Start a dedicated instance](managed-instances.md) with `ManagedInstance::start`. | Check that the selected program became ready with the expected identity and private state. |
| 04 | [Connect or reconnect](getting-started.md) with `Client::connect`, `ManagedInstance::connect_existing`, or `reconnect_management`. | Check the chosen management endpoint, engine version, and device. An external connection may have limited process evidence. |
| 05 | [Stop an owned instance](managed-instances.md) with `shutdown_and_verify`. | Check exit of the original process tree and state release. On a borrowed connection, `request_shutdown` reports the request and its available reply. |
| 06 | [Force an owned instance to stop](managed-instances.md) with `force_stop`. | Check the exact owned tree and the resulting exit. Choose force explicitly when appropriate. |
| 07 | [Restart or select another program](managed-instances.md) with `restart_and_verify` or `restart_with_program_and_verify`. | Check the old exit, selected program, and new generation's identity and readiness. Reacquire the active management handle. |
| 08 | [Back up stopped instance state](program-upgrades.md) with `backup_state`. | Check clean-stop eligibility and the complete snapshot manifest. The snapshot covers private instance state. |
| 09 | [Restore a state snapshot](program-upgrades.md) with `open` and `restore_to`. | Verify the manifest, file lengths and hashes, and new destination. Check startup separately if needed. |
| 10 | [Use remote tunnel management](remote-management.md) with `remote_tunnel` and `probe_device_tunnel`. | A probe reports the selected path's result. An authorized management connection also needs the expected device and supported entitlement. |
| 11 | [Use a native GUI session](management-authentication.md) with `GuiSession::login_with_outcome` and `logout_and_verify`. | Check version and device before accepting a session. On logout, read whether the original cookie is rejected. |
| 12 | [Change GUI authentication](management-authentication.md) with `set_local_gui_credentials_and_verify`, `set_gui_auth_mode`, or the LDAP preference scope. | Check the stored mode and username and, when explicitly attempted, the new GUI login. LDAP settings alone establish configuration. |
| 13 | [Rotate an API key](management-authentication.md) with `rotate_api_key` or `reconnect_with_api_key`. | Verify the new credential on the same device and check the outcome for the old credential. |
| 14 | [Change the management listener](gui-listener.md) with `execute_gui_listener_change_persisted` and `observe_listener`. | Check the original reply and the intended listener independently. The fixed engine can keep its GUI listener active after a disable request. |
| 15 | [Review and apply settings](control-preview.md) with `preview_settings_changes` and `commit_settings_preview`. | Inspect each selected field's original change and actual readback. Keep successful fields and review unresolved results. |
| 16 | [Save a configuration snapshot](configuration.md) with `save_configuration_and_verify`. | Check that the selected complete document matches the original instance. The native application flag and disk persistence are separate facts. |
| 17 | [Change preferences or defaults](configuration.md) with `change_preferences_and_verify`. | Check the selected fields and native application flag. A template applies to future registrations. |
| 18 | [Use an official account on the selected engine](official-accounts.md) with `login_official_account_and_verify` and `logout_official_account_and_verify`. | Check observed account state and an expected UID when supplied. Service-wide session revocation needs separate evidence. |
| 19 | [Refresh a license or request a trial](licenses.md) with `request_license_and_verify`. | Check the actual record, validity and trial status on this instance. Refreshing a license is separate from obtaining one or verifying a specific entitlement. |
| 20 | [Register or join a P2P folder](sharing.md) with `create_folder_and_verify` or `join_folder_and_verify`. | Check the registration ID, path, key permission and selected initial fields. Verify peer delivery separately. |
| 21 | [Update a P2P folder](sharing.md) with `update_folder_and_verify`, or use [Local-API](local-api.md) collection and item methods. | Check the selected identity, fields and, for collection replacement, membership. The independent Local-API can require a separate entitlement. |
| 22 | [Pause or resume a folder](sync-observation.md) with `set_folder_pause_and_verify`. | Inspect the configuration pause bit and the folder's separately observed activity. |
| 23 | [Unregister a folder and keep files](sharing.md) with `unregister_folder_and_verify`. | Check that the exact original registration is absent. Confirm file retention using access to the selected files. |
| 24 | [Register or update a peer](devices.md) with `create_device_and_verify` or `update_device_and_verify`. | Check the device ID and requested fields. Read actual connections for live reachability. |
| 25 | [Pause or resume a peer](devices.md) with `set_device_pause_and_verify`. | Compare the requested configuration value with actual connection state when it can be observed. |
| 26 | [Remove a device](control-observation.md) with `execute_device_removal_persisted` or `disconnect_and_remove_device`. | Check the exact registration and, when requested, observed disconnect. Recovery from a saved receipt is read-only. |
| 27 | [Generate or validate a share key](sharing.md) with `generate_share` or `validate_share_key`. | Check the returned key pair or permission for the supplied key. Generating again produces a different pair. |
| 28 | [Share with a peer or edit its encryption password](invitations.md) with `change_folder_peer_and_verify`. | Check the selected association and preservation of other peers. File delivery and actual encryption need separate native evidence. |
| 29 | [Manage offers and ignore rules](invitations.md) with `pending_folders`, `dismiss_folder_offer`, `ignore_folder_offer`, or `unignore_folder`. | Check the exact offering device and folder, or persistent ignore state. Positive pending-device creation and dismissal require a real native record. |
| 30 | [Scan a folder, subpaths, or all folders](scan-control.md) with `scan_and_observe`. | Check the selected scope and observed scan phases. An event gap or concurrent scan can leave attribution unconfirmed. |
| 31 | [Verify a file batch at selected receivers](sync-observation.md) with `observe_delivery_batch` or `scan_delivery_batch_and_verify`. | Compare length and SHA-256 at each authorized receiver. Strict verification checks receiver access before scanning. If access is lost after the scan, keep the original reply and mark delivery unconfirmed until the files can be checked. |
| 32 | [Change selective synchronization](selective-sync.md) with `set_selective_path_and_verify`. | Check the selected path, snapshot and applicable Pro permission. Verify expected file presence or removal separately. |
| 33 | [Change ignore rules](ignore-patterns.md) with `change_ignore_patterns_and_verify`. | Check matching rules in the selected folder or future template. Check actual index or delivery effects separately. |
| 34 | [Change scan schedule or file priority](scheduling.md) with `update_folder_scan_configuration`, `set_folder_pull_order`, or `prioritize_file_and_verify`. | Check stored schedule and order, or the requested file's actual first-page position. If it leaves the queue, check the resulting file. |
| 35 | [Configure network and transport policy](network.md) with `change_preferences_and_verify`. | Check stored settings plus applicable live listeners, discovery, tracker, NAT, or connections. To verify transfer, confirm the selected path and file. |
| 36 | [Enable, disable, or check a relay](relay.md) with the relay preference scope and `probe_relay`. | Check stored values, service state, and any explicit probe separately. Check peer connection type and received bytes to verify a relay transfer. |
| 37 | [Consume and resume event streams](events.md) with `subscribe_events`, `subscribe_disk_events`, or `subscribe_index_events`. | Read events and explicit gaps using the correct source, generation and consumer cursor. |
| 38 | [Revert receiving changes or override remote edits](recovery.md) with `recover_folder_and_verify`. | The native request affects the entire folder. Check the selected current bytes on the receiving instance or explicitly authorized peers. |
| 39 | [Repair the folder marker](recovery.md) with `repair_folder_marker_and_verify`. | Check the exact folder path, native mount, and marker directory. Check restored scanning and preserved files separately. |
| 40 | [Download a single file](file-transfers.md) with `download_file_and_verify` or take a stream from `download_resource`. | Check file type, selected range and length. For managed output, verify full SHA-256 before publication. Opt in to safe resume when the source supplies trusted identity. |
| 41 | [Export a directory or selected items](file-transfers.md) with `download_resource_archive` or `download_selected_resources`. | Check the archive stream for the selected scope. Inspect members separately if you require a complete manifest. |
| 42 | [Upload a file or write text](file-transfers.md) with `upload_file_and_verify` or `write_resource_text`. | Check the selected target, contents and conflict policy. Recheck the exact resource after an uncertain response. |
| 43 | [Create a directory](target-directories.md) with `create_directory_and_verify`. | Check the exact directory in a file-manager volume, the native picker, or a Local Sync backend. Parent creation can have its own effects. |
| 44 | [Copy files or directories](file-mutations.md) with `copy_file_and_verify` or `copy_resource`. | Check destination and source separately. For directory merge, inspect expected children and any partial effect. |
| 45 | [Move or rename a resource](file-mutations.md) with `move_file_and_verify` or `move_resource`. | Check target content and whether the original path is still present. The fixed Windows engine has a directory-merge limitation. |
| 46 | [Delete a file or directory](file-mutations.md) with `delete_resource_and_verify`. | Check whether the exact resource remains. Partial deletion and a failed read stay visible in the report. |
| 47 | [Select version retention or archive storage](file-history.md) with `change_versioning_and_verify`. | Check the versioner configuration and, for a folder, any available archive inventory. Verify actual storage effects separately. |
| 48 | [Restore archive versions](file-history.md) with `restore_versions_and_verify`. | Check the target clock and the exact historical selection before dispatch. Compare each selected file's length and digest after the request. |
| 49 | [Manage audit history](file-history.md) with `set_audit_history_settings`, `audit_history`, or `reset_audit_history_and_verify`. | Check entitlement and actual recorded or cleared entries. Preserve any new records the engine created around the clear. |
| 50 | [Register, edit, or remove a Local Sync job](local-sync.md) with `create_local_sync_job_and_verify` or `change_local_sync_registration_and_verify`. | Check the exact job and endpoint settings. Automatic triggers and file effects need direct evidence on the engine holding the applicable entitlement. |
| 51 | [Check or browse a storage endpoint](local-sync.md) with `probe_storage_endpoint` or `browse_storage_endpoint`. | Check the selected backend's native flags or exact listing. Verify the data operation you need separately. |
| 52 | [Build and read a Local Sync preview](local-sync.md) with `preview_local_sync_and_verify`. | Check the exact preview, its operation, and selected action pages. A preview does not transfer files. |
| 53 | [Execute reviewed Local Sync actions](local-sync.md) with `execute_local_sync_preview` or `observe_local_sync_execution`. | Check the exact run, terminal state, and per-action results. Verify target bytes when delivery is required. |
| 54 | [Pause, resume, or stop a Local Sync run](local-sync.md) with `control_local_sync_run_and_verify`. | Check the specific job and run state. A stopped run can leave already written files. |
| 55 | [Resolve a Local Sync conflict](local-sync.md) with `resolve_local_sync_conflict_and_verify`. | Check the replacement preview, selected scope and remaining conflicts. Execute the reviewed replacement separately. |
| 56 | [Rebuild Local Sync markers or baseline](local-sync.md) with `repair_local_sync_and_verify`. | Check the reviewed job, original reply and status or replacement preview. Review that preview before deciding whether to run it. |
| 57 | [Read Local Sync events](local-sync.md) with `subscribe_local_sync_events` or `local_sync_events`. | Inspect the actual cursor and reported missed or reset state. Read a run receipt separately for its outcome. |
| 58 | [Request a native index reset](core-maintenance.md) with `request_index_reset`. | Check the requested scope and acknowledgement. Observe old exit, new readiness, reconstructed index and file retention independently. |
| 59 | [Clean native temporary files](core-maintenance.md) with `request_folder_temporary_cleanup`. | Check the exact folder and native acknowledgement. Inspect remaining files to establish which paths changed. |
| 60 | [Record or clear errors and change core log levels](core-maintenance.md) with `change_core_logging_and_verify`. | Check a correlated record, old and new error counts, or the actual package levels separately from the original reply. |
| 61 | [Collect a profile, support bundle, or usage snapshot](core-maintenance.md) with `collect_core_profile`, `collect_core_support_bundle`, or `collect_native_usage_report`. | Verify the bounded output and its format. Collecting a profile can trigger native work. |
| 62 | [Request a native folder or browser opener](native-helpers.md) with `request_native_folder_open` or `request_native_browser`. | Check the native acknowledgement or helper exit. Confirm an actual user-visible window on its host if needed. |
| 63 | [Request a Linux file-watch limit](native-helpers.md) with `request_native_file_watch_limit`. | Check the selected host's actual persisted or live value separately from helper exit. |
| 64 | [Read a target snapshot](native-hardware.md) with `ping`, `version`, `system_status`, or the selected native read. | Inspect the actual response for the selected target; verify the relevant identity or path when scope matters. |
| 65 | [Request native random output](native-helpers.md) with `native_random_string` or `native_random_number`. | Read the value returned by this request. A lost reply leaves that particular value unknown. |
| 66 | [Verify a long-running multi-peer delivery](control-observation.md) with `scan_delivery_batch_and_verify` for an authorized batch. Use registration and sharing to set up the named peers, and `observe_folder` when you also need native progress. | Check each named node and receiving file. An application can preserve observations while a native transfer continues. |
| 67 | [Send a raw request or read a GUI resource](native-gui-resources.md) with `raw_request` or `raw`. | Inspect the raw response for the chosen endpoint. Supply the intended side-effect class before requesting any mutation. |
| 68 | [Read shell-completion instructions](native-helpers.md) with `native_completion_instructions`. | Check native output and helper exit. Inspect the selected shell separately if enabling completion matters. |
| 69 | [Probe target path writeability](target-directories.md) with `probe_target_path_writeability`. | Keep the native snapshot. The fixed engine can report false for a known writable path. |
| 70 | [Check a dedicated Local-API read](local-api.md) with `LocalApiClient::connect` and `preflight_folder_need`. | Verify endpoint, version, device, and the selected read. Distinguish a complete access refusal from a native license requirement. |
| 71 | [Read a pending native link](native-helpers.md) with `pending_native_link`. | Read the current link or empty result. Keep the link private and explicitly decide whether to use it. |
| 72 | [Inspect or reset a stopped database](core-maintenance.md) with `run_database_command`. | Check the exact command and its native result. A stopped-state operation can change clean-backup eligibility. |
| 73 | [Verify an introduced peer](invitations.md) with `observe_folder_introduction`. | Check the specific device origin and folder membership. Compare observations to establish addition or withdrawal. |
| 74 | [Read native paths from stopped state](native-helpers.md) with `inspect_native_storage_paths`. | Check the real CLI exit and effective locations on that engine. Check clean-stop backup eligibility separately. |

## Run from an unpacked package

The packaged guides contain focused Rust examples. The package also includes
public-API integration tests. The independent consumer helper copies those
tests into a new Cargo project and uses the verified, separately unpacked
crate as its library dependency. See [CI acceptance](ci-acceptance.md) for
engine selection, isolated fixtures and replay. Do not point these examples
or test fixtures at an existing instance with user data.
