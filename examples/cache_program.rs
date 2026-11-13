//! Explicit fixed cache preparation; never starts a vendor program.
use std::path::PathBuf;
use verysync_sidecar::{official_programs, CachePolicy, CacheStatus, ProgramCache};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let target = args
        .next()
        .and_then(|s| s.into_string().ok())
        .ok_or("usage: cache_program TARGET CACHE_ROOT [SOURCE_URL]")?;
    let root = PathBuf::from(args.next().ok_or("explicit cache root required")?);
    let asset = official_programs()?
        .into_iter()
        .find(|a| a.target().id() == target)
        .ok_or("target must be listed in the fixed catalog")?;
    let mut cache = ProgramCache::new(root)?;
    if let Some(source) = args.next() {
        cache = cache.source_url(
            source
                .into_string()
                .map_err(|_| "source URL must be UTF-8")?
                .parse()?,
        )?;
    }
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let program = cache.resolve(asset, CachePolicy::DownloadMissing).await?;
    println!(
        "{}",
        serde_json::json!({"target":target,"downloaded":program.status() == CacheStatus::Downloaded,"program":format!("{:?}",program.program().path())})
    );
    Ok(())
}
