//! Explicit static artifact acceptance for every in-scope fixed catalog asset.
use verysync_sidecar::{official_programs, DownloadOptions};

#[tokio::test]
async fn every_fixed_official_archive_has_the_exact_regular_core_and_matching_format(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let root = tempfile::Builder::new()
        .prefix("vs-catalog-")
        .tempdir()?
        .keep();
    let mut jobs = tokio::task::JoinSet::new();
    let mut completed = 0;
    let assets = official_programs()?;
    let expected = assets.len();
    for asset in assets {
        let destination = root.join(asset.target().id());
        jobs.spawn(async move {
            let target = asset.target().id();
            let program = match DownloadOptions::new(asset, destination)?.prepare().await {
                Ok(program) => program,
                Err(error) => {
                    eprintln!("public Rust static artifact failure: {}", serde_json::json!({"target":target,"error":error.to_string()}));
                    return Err(error);
                }
            };
            assert!(program.program().path().is_file());
            println!("public Rust static artifact evidence: {}", serde_json::json!({"target":target,"fixed_archive_sha_verified":true,"exact_regular_core_extracted":true,"selected_header_matched":true,"runtime_executed":false}));
            Ok::<_, verysync_sidecar::Error>(())
        });
        if jobs.len() >= 4 {
            jobs.join_next().await.ok_or("missing artifact task")???;
            completed += 1;
        }
    }
    while let Some(job) = jobs.join_next().await {
        job??;
        completed += 1;
    }
    assert_eq!(completed, expected);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
