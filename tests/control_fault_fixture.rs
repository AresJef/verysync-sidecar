//! Calibrate the witness independently of the new public control operations.

#[path = "common/control_fault_origin.rs"]
mod control_fault_origin;
use control_fault_origin::{
    assert_read_only, Delivery, Method, Origin, Phase, Response, Route, TestResult, Witness,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, Error, GuiListenAddress, GuiListenerPatch, ManagementEndpoint,
};

const KEY: &str = "synthetic-no-share-api-key";
const DEVICE: &str = "AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA";
const BEFORE: &str = "127.0.0.1:44001";
const AFTER: &str = "127.0.0.1:44002";

#[tokio::test]
async fn independent_witness_separates_single_drop_and_readback_results() -> TestResult {
    for (apply, acknowledge) in [(true, false), (false, false), (true, true)] {
        let applied = Arc::new(AtomicBool::new(false));
        let witness = Witness::new();
        let state = Arc::clone(&applied);
        let origin = Origin::start("fixture", witness.clone(), move |_, request| {
            let state = Arc::clone(&state);
            async move {
                assert_eq!(
                    request.credential.as_ref().and_then(|v| v.to_str().ok()),
                    Some(KEY)
                );
                match (request.method, request.route) {
                    (Method::Get, Route::Version) => Response::json(&serde_json::json!({
                        "version":"v2.33.2", "os":"linux", "arch":"amd64"
                    })),
                    (Method::Get, Route::Identity) => Response::json(&serde_json::json!({
                        "myID":DEVICE
                    })),
                    (Method::Get, Route::Gui) => Response::json(&serde_json::json!({
                        "enabled":true, "authMode":"static", "user":"", "password":"",
                        "apiKey":KEY, "useTLS":false, "unixSocketPermissions":"",
                        "address":if state.load(Ordering::SeqCst) { AFTER } else { BEFORE }
                    })),
                    (Method::Patch, Route::Gui) => {
                        let submitted: serde_json::Value = serde_json::from_slice(&request.body)?;
                        assert_eq!(submitted, serde_json::json!({"address":AFTER}));
                        state.store(apply, Ordering::SeqCst);
                        if acknowledge {
                            Response::json(&serde_json::json!({}))
                        } else {
                            Ok(Response::drop_reply(Some(200)))
                        }
                    }
                    _ => Err("synthetic backend received an unexpected request".into()),
                }
            }
        })
        .await?;
        assert!(origin.address().ip().is_loopback());
        let options = || -> TestResult<ConnectOptions> {
            Ok(ConnectOptions::new(
                ManagementEndpoint::http(&origin.url())?,
                ApiKey::new(KEY)?,
            ))
        };
        let client = Client::connect(options()?).await?;
        let result = client
            .update_gui_listener(
                &GuiListenerPatch::default().address(GuiListenAddress::tcp(AFTER)?),
            )
            .await;
        if acknowledge {
            assert_eq!(result?.acknowledgement.status(), 200);
        } else {
            assert!(matches!(result, Err(Error::MutationOutcomeUnknown { .. })));
        }
        drop(client);
        witness.recovery()?;
        let recovery = Client::connect(options()?).await?;
        assert_eq!(
            recovery.gui_listener().await?.address.tcp_authority(),
            Some(if apply { AFTER } else { BEFORE })
        );
        let rows = witness.rows()?;
        let writes: Vec<_> = rows
            .iter()
            .filter(|row| row.method == Method::Patch)
            .collect();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].phase, Phase::Submission);
        assert_eq!(writes[0].backend_status, Some(200));
        assert_eq!(
            writes[0].delivery,
            if acknowledge {
                Delivery::ResponseSent
            } else {
                Delivery::DroppedAfterBackendResponse
            }
        );
        let reads: Vec<_> = rows
            .into_iter()
            .filter(|row| row.phase == Phase::Recovery)
            .collect();
        assert_read_only(&reads)?;
        let doc = serde_json::to_string(&reads)?;
        assert!(!doc.contains(KEY) && !doc.contains(BEFORE) && !doc.contains(AFTER));
    }
    Ok(())
}

#[tokio::test]
async fn independent_witness_detects_an_extra_write_and_a_get_with_side_effects() -> TestResult {
    let witness = Witness::new();
    let origin = Origin::start("fixture", witness.clone(), |_, _| async {
        Ok(Response::backend_disconnected())
    })
    .await?;
    witness.recovery()?;
    let client = reqwest::Client::builder().no_proxy().build()?;
    for (method, route) in [
        (reqwest::Method::PATCH, "rest/config/gui"),
        (reqwest::Method::GET, "rest/svc/folder/secret"),
    ] {
        let response = client
            .request(method, format!("{}{route}", origin.url()))
            .send()
            .await?;
        assert_eq!(response.status(), 405);
    }
    let watched = witness.rows()?;
    assert_eq!(watched.len(), 2);
    assert!(watched
        .iter()
        .all(|row| row.delivery == Delivery::RejectedByFixture));
    for row in watched {
        assert!(assert_read_only(&[row]).is_err());
    }
    Ok(())
}
