//! Select a native file-manager path resolving to only the task-owned profile.
use std::path::{Path, PathBuf};
use verysync_sidecar::{ManagedInstance, ResourcePath, ResourceVolume, TargetPath};
type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn canonical(path: &Path) -> std::io::Result<PathBuf> {
    #[cfg(windows)]
    {
        dunce::canonicalize(path)
    }
    #[cfg(not(windows))]
    {
        std::fs::canonicalize(path)
    }
}
pub fn owned_base(
    core: &ManagedInstance,
    volumes: &[ResourceVolume],
) -> TestResult<(PathBuf, ResourcePath)> {
    let profile = canonical(&core.state_directory().join("profile"))?;
    let mut candidates = Vec::new();
    let mut diagnostic = Vec::new();
    for volume in volumes {
        let path = Path::new(&volume.path);
        let root = canonical(path);
        let relative = root
            .as_ref()
            .ok()
            .and_then(|root| profile.strip_prefix(root).ok());
        diagnostic.push(serde_json::json!({"local_kind":volume.kind=="local","kind_empty":volume.kind.is_empty(),
            "locator_absolute":path.is_absolute(),"canonical_available":root.is_ok(),
            "exact_owned_profile":relative.is_some_and(|p|p.as_os_str().is_empty()),
            "contains_owned_profile":relative.is_some(),"locator_components":path.components().count()}));
        if volume.kind != "local" {
            continue;
        }
        let Some(relative) = relative else {
            continue;
        };
        let base = if relative.as_os_str().is_empty() {
            ResourcePath::root(volume.id.clone(), TargetPath::local(&profile).style())
        } else {
            ResourcePath::relative(volume.id.clone(), &TargetPath::local(relative))?
        };
        candidates.push((relative.components().count(), base));
    }
    candidates.sort_by_key(|(depth, _)| *depth);
    let Some((_, base)) = candidates.into_iter().next() else {
        eprintln!(
            "private resource volume ownership diagnostic: {}",
            serde_json::to_string(&diagnostic)?
        );
        return Err("no actual local mount resolves to the exact task-owned profile".into());
    };
    Ok((profile, base))
}
