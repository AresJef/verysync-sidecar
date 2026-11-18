//! Fixed, observed FTP-refusal scope; other artifacts retain positive requirements.
use serde_json::Value;
use std::{io::Read, path::Path};
use verysync_sidecar::ManagedInstance;

pub fn observed_standard_package(core: &ManagedInstance) -> Option<String> {
    let binary = core.selected_program().path().canonicalize().ok()?;
    let receipt = read_receipt(&binary)?;
    let sha: String = core
        .program_info()
        .sha256
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if !matches_receipt(
        &receipt,
        &sha,
        &core.program_info().version,
        std::env::consts::OS,
        std::env::consts::ARCH,
    ) {
        return None;
    }
    receipt["package"].as_str().map(str::to_owned)
}
fn read_receipt(binary: &Path) -> Option<Value> {
    let path = binary.parent()?.join("receipt.json");
    let metadata = std::fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 8192 {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(8193)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > 8192 {
        return None;
    }
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    let recorded = Path::new(value["binary"].as_str()?);
    if !recorded.is_absolute() || recorded.canonicalize().ok()? != binary {
        return None;
    }
    Some(value)
}
fn matches_receipt(receipt: &Value, binary_sha: &str, version: &str, os: &str, arch: &str) -> bool {
    let package = match (os, arch) {
        ("macos", "x86_64") => "macos-amd64-standard",
        ("macos", "aarch64") => "macos-arm64-standard",
        ("linux", "x86_64") => "linux-amd64-standard",
        ("linux", "aarch64") => "linux-arm64-standard",
        ("windows", "x86_64") => "windows-amd64-standard",
        ("windows", "aarch64") => "windows-arm64-standard",
        _ => return false,
    };
    if receipt["package"] != package
        || receipt["version"] != version
        || version != "v2.33.2"
        || receipt["binary_sha256"] != binary_sha
    {
        return false;
    }
    let Ok(fingerprints) = serde_json::from_str::<Value>(include_str!(
        "../../releases/verysync-v2.33.2-standard-binaries.json"
    )) else {
        return false;
    };
    let Ok(catalog) =
        serde_json::from_str::<Value>(include_str!("../../releases/verysync-v2.33.2.json"))
    else {
        return false;
    };
    let Some(known) = fingerprints["packages"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["id"] == package))
    else {
        return false;
    };
    let Some(official) = catalog["packages"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["id"] == package))
    else {
        return false;
    };
    fingerprints["version"] == version
        && catalog["version"] == version
        && official["variant"] == "standard"
        && official["alpha_target"] == true
        && receipt["archive_sha256"] == official["sha256"]
        && receipt["archive_sha256"] == known["archive_sha256"]
        && known["binary_sha256"] == binary_sha
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn standard_receipt_scope_rejects_legacy_unknown_and_mismatched_artifacts() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../releases/verysync-v2.33.2-standard-binaries.json"
        ))
        .unwrap();
        for row in fixture["packages"].as_array().unwrap() {
            let id = row["id"].as_str().unwrap();
            let parts: Vec<_> = id.split('-').collect();
            let os = parts[0];
            let arch = if parts[1] == "amd64" {
                "x86_64"
            } else {
                "aarch64"
            };
            let sha = row["binary_sha256"].as_str().unwrap();
            let valid = serde_json::json!({"package":id,"version":"v2.33.2","binary_sha256":sha,"archive_sha256":row["archive_sha256"]});
            assert!(matches_receipt(&valid, sha, "v2.33.2", os, arch));
            for (field, value) in [
                ("package", format!("{os}-{}-legacy", parts[1])),
                ("package", "linux-386-standard".into()),
                ("version", "v2.33.1".into()),
                ("binary_sha256", "0".repeat(64)),
                ("archive_sha256", "0".repeat(64)),
            ] {
                let mut changed = valid.clone();
                changed[field] = value.into();
                assert!(
                    !matches_receipt(&changed, sha, "v2.33.2", os, arch),
                    "unobserved artifact must retain positive FTP acceptance"
                );
            }
            assert!(!matches_receipt(&Value::Null, sha, "v2.33.2", os, arch));
            assert!(!matches_receipt(
                &valid,
                &"0".repeat(64),
                "v2.33.2",
                os,
                arch
            ));
            assert!(!matches_receipt(&valid, sha, "v2.33.1", os, arch));
            assert!(!matches_receipt(&valid, sha, "v2.33.2", "linux", "mips"));
        }
    }
    #[test]
    fn missing_oversized_invalid_and_aliased_receipts_do_not_authorize_an_exception() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("owned engine");
        std::fs::write(&file, b"not executed").unwrap();
        let binary = file.canonicalize().unwrap();
        let receipt = binary.parent().unwrap().join("receipt.json");
        assert!(read_receipt(&binary).is_none());
        std::fs::write(&receipt, vec![b' '; 8193]).unwrap();
        assert!(read_receipt(&binary).is_none());
        let valid = serde_json::to_vec(&serde_json::json!({"binary":binary})).unwrap();
        std::fs::write(&receipt, &valid).unwrap();
        assert!(read_receipt(&binary).is_some());
        std::fs::write(
            &receipt,
            serde_json::to_vec(&serde_json::json!({"binary":"relative-engine"})).unwrap(),
        )
        .unwrap();
        assert!(read_receipt(&binary).is_none());
        std::fs::write(&receipt, [255]).unwrap();
        assert!(read_receipt(&binary).is_none());
        std::fs::remove_file(&receipt).unwrap();
        std::fs::create_dir(&receipt).unwrap();
        assert!(read_receipt(&binary).is_none());
        std::fs::remove_dir(&receipt).unwrap();
        #[cfg(unix)]
        {
            let target = root.path().join("other.json");
            std::fs::write(&target, valid).unwrap();
            std::os::unix::fs::symlink(&target, &receipt).unwrap();
            assert!(read_receipt(&binary).is_none());
        }
    }
}
