//! Explicit native external wallpaper-resource investigation.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use std::time::Duration;
use verysync_sidecar::{Error, ManagedInstance, NativeWallpaperStatus};
#[tokio::test]
async fn actual_native_wallpaper_resource_and_conditional_response() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-wallpaper-")
        .tempdir()?
        .keep();
    let state = root.join("core");
    std::fs::write(root.join("sample.txt"), b"retained wallpaper fixture bytes")?;
    let mut owner = ManagedInstance::start(options(&state)?).await?;
    let identity = owner.client().instance().device_id.clone();
    let config = std::fs::read(state.join("setting.dat"))?;
    owner.client().system_status().await?;
    let permitted = std::env::var("VERYSYNC_TEST_WALLPAPER_SOURCE_ALLOWED").as_deref() == Ok("1");
    let response = owner.client().native_wallpaper(None).await;
    if !permitted {
        assert!(matches!(response,Err(Error::Http{response}) if response.status()==500));
        assert_eq!(std::fs::read(state.join("setting.dat"))?, config);
        assert_eq!(owner.client().system_status().await?.device_id, identity);
        assert_eq!(
            std::fs::read(root.join("sample.txt"))?,
            b"retained wallpaper fixture bytes"
        );
        let exit = owner.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
        std::fs::remove_dir_all(root)?;
        println!("native_wallpaper_source_denial_preserved=true source_bypass_not_enabled=true normal_owned_tree_exit=true");
        return Ok(());
    }
    let response = response?;
    eprintln!(
        "native-wallpaper-first status={:?} bytes={}",
        response.status(),
        response.body_bytes().len()
    );
    assert_eq!(response.status(), NativeWallpaperStatus::Image);
    assert!(response.body_bytes().len() > 100);
    let media = response
        .headers()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .ok_or("native media missing")?
        .1;
    assert!(std::str::from_utf8(media)?.starts_with("image/"));
    let etag = std::str::from_utf8(
        response
            .headers()
            .find(|(k, _)| k.eq_ignore_ascii_case("etag"))
            .ok_or("native tag missing")?
            .1,
    )?;
    let conditional = owner.client().native_wallpaper(Some(etag)).await?;
    eprintln!(
        "native-wallpaper-conditional status={:?} bytes={}",
        conditional.status(),
        conditional.body_bytes().len()
    );
    assert_eq!(conditional.status(), NativeWallpaperStatus::NotModified);
    assert!(conditional.body_bytes().is_empty());
    assert_eq!(owner.client().system_status().await?.device_id, identity);
    assert_eq!(std::fs::read(state.join("setting.dat"))?, config);
    assert_eq!(
        std::fs::read(root.join("sample.txt"))?,
        b"retained wallpaper fixture bytes"
    );
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!("native_wallpaper_image_resource=true native_conditional_304=true image_never_saved_or_applied=true sample_config_identity_preserved=true normal_owned_tree_exit=true");
    Ok(())
}
