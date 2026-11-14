//! Native resources and independently decoded fixed-program QR reference vectors.
use super::managed_fixture::{options, TestResult};
use sha2::{Digest, Sha256};
use std::time::Duration;
use verysync_sidecar::{Error, ManagedInstance};

#[tokio::test]
async fn actual_native_gui_resources_preserve_identity_language_preferences_and_qr_payloads(
) -> TestResult {
    let root = tempfile::Builder::new().prefix("vsqr-").tempdir()?.keep();
    let mut owner = ManagedInstance::start(options(&root.join("core"))?).await?;
    let id = owner.client().instance().device_id.clone();
    let metadata = owner.client().native_gui_metadata().await?;
    assert_eq!(metadata.device_id, id);
    assert_eq!(
        metadata.short_device_id,
        id.as_str().split('-').next().ok_or("short ID absent")?
    );
    assert!(metadata.authenticated && metadata.authentication_enabled);
    assert!(!format!("{metadata:?}").contains(id.as_str()));
    assert_eq!(
        owner.client().native_preferred_languages("").await?,
        vec![""]
    );
    assert_eq!(
        owner
            .client()
            .native_preferred_languages("fr-FR, en;q=0.8, zh-CN;q=0.6")
            .await?,
        vec!["fr-fr", "en", "zh-cn"]
    );
    assert_eq!(
        owner
            .client()
            .native_preferred_languages("en;q=0.2, fr-FR;q=0.9")
            .await?,
        vec!["fr-fr", "en"]
    );
    // These two actual native PNGs were independently decoded with Apple Vision
    // to the exact texts below. Matching bytes checks encoded payloads across
    // targets without adding an image decoder to the SDK or Cargo build.
    for (text, hash, width) in [
        (
            "verysync-sidecar synthetic QR & + %",
            "17bdc57bc06a37b1699451aaa06c212effd9ad7d82bf0198f4416666beeb64f0",
            296,
        ),
        (
            "verysync-sidecar 测试 QR",
            "e768265b279d0712f143fd0cf702ab1ff45dec8fadb1fe3fb6e8fefe11fef34d",
            264,
        ),
    ] {
        let qr = owner.client().native_qr_code(text).await?;
        assert_eq!(qr.width, width);
        assert_eq!(qr.height, width);
        assert_eq!(format!("{:x}", Sha256::digest(qr.png_bytes())), hash);
        assert_eq!(
            owner.client().native_qr_code(text).await?.png_bytes(),
            qr.png_bytes()
        );
        assert!(!format!("{qr:?}").contains(text));
    }
    assert!(matches!(
        owner.client().native_qr_code(&"a".repeat(4000)).await,
        Err(Error::Http { .. })
    ));
    assert!(owner.client().folders().await?.is_empty());
    assert_eq!(owner.client().system_status().await?.device_id, id);
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!("native_gui_resource_effects=9 identity_checked_metadata=true explicit_language_header_only=true independent_decoded_qr_reference_match=true native_capacity_failure_retained=true no_gui_or_registration=true");
    Ok(())
}
