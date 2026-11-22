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
    let root = PathBuf::from(
        args.next()
            .ok_or("Supply the directory for the verified program cache.")?,
    );
    let asset = official_programs()?
        .into_iter()
        .find(|a| a.target().id() == target)
        .ok_or("This target is missing from the program catalog. Choose a listed system and architecture.")?;
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
        return Err("Supply only the target, cache directory and optional source URL.".into());
    }
    let program = cache.resolve(asset, CachePolicy::DownloadMissing).await?;
    if program.status() == CacheStatus::Downloaded {
        eprintln!("Downloaded and verified the selected VerySync program. It is ready to start explicitly.");
    } else {
        eprintln!("Verified the selected VerySync program in the local cache. It is ready to start explicitly.");
    }
    println!(
        "{}",
        serde_json::json!({"target":target,"downloaded":program.status() == CacheStatus::Downloaded,"program":format!("{:?}",program.program().path())})
    );
    Ok(())
}
