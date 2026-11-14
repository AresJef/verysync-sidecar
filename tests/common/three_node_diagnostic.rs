//! Fixed stage names and bounded summaries of only this fixture's private logs.
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    io::Read,
    path::{Path, PathBuf},
};

pub struct Phase {
    root: PathBuf,
    current: Cell<&'static str>,
    complete: Cell<bool>,
}
impl Phase {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            current: Cell::new("prepare"),
            complete: Cell::new(false),
        }
    }
    pub fn set(&self, stage: &'static str) {
        self.current.set(stage);
        eprintln!("three-node stage: {stage}");
    }
    pub fn complete(&self) {
        self.complete.set(true);
    }
}
impl Drop for Phase {
    fn drop(&mut self) {
        if self.complete.get() {
            return;
        }
        let logs: Vec<_> = ["a", "b", "c"]
            .into_iter()
            .map(|core| log_summary(&self.root, core))
            .collect();
        eprintln!(
            "three-node original failure diagnostics: {}",
            json!({"stage":self.current.get(),
            "private_log_prefix_summaries":logs,"raw_arguments_paths_keys_and_log_bodies_omitted":true,
            "original_deadlines_and_failure_retained":true})
        );
    }
}

fn log_summary(root: &Path, core: &'static str) -> serde_json::Value {
    let read =
        std::fs::File::open(root.join(core).join(".verysync-sidecar-core.log")).and_then(|file| {
            let mut bytes = Vec::new();
            file.take(65537).read_to_end(&mut bytes)?;
            Ok(bytes)
        });
    let mut bytes = match read {
        Ok(bytes) => bytes,
        Err(error) => {
            return json!({"core":core,"read":false,"kind":format!("{:?}",error.kind()),"native_code":error.raw_os_error()})
        }
    };
    let truncated = bytes.len() > 65536;
    bytes.truncate(65536);
    let text = String::from_utf8_lossy(&bytes);
    let lower = text.to_ascii_lowercase();
    let frames: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("verysync.com/verysync/verysync/"))
        .filter_map(|line| {
            let (name, _arguments) = line.split_once("(0x")?;
            (name.len() <= 192
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_./*()-".contains(c)))
            .then_some(name.to_owned())
        })
        .take(8)
        .collect();
    json!({"core":core,"read":true,"bounded_bytes":bytes.len(),"truncated":truncated,
        "prefix_sha256":format!("{:x}",Sha256::digest(&bytes)),
        "has_panic_marker":lower.contains("panic:"),"has_fatal_marker":lower.contains("fatal error:"),
        "has_nil_pointer_marker":lower.contains("invalid memory address")||lower.contains("nil pointer"),
        "has_exit_marker":lower.contains("exiting"),"native_function_names_only":frames})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_failure_summary_bounds_reads_and_omits_go_arguments_and_malformed_frames(
    ) -> std::io::Result<()> {
        let root = tempfile::tempdir()?;
        std::fs::create_dir(root.path().join("a"))?;
        let secret = "synthetic-private-api-token";
        let mut log=format!("panic: invalid memory address: {secret}\nverysync.com/verysync/verysync/lib/model.(*model).Closed(0xCAFEBABE, {secret})\n\t/private/synthetic-private-path/db.go:42\nverysync.com/verysync/verysync/{secret}\n");
        log.push_str(&"x".repeat(70000));
        std::fs::write(
            root.path().join("a").join(".verysync-sidecar-core.log"),
            log,
        )?;
        let summary = log_summary(root.path(), "a");
        assert_eq!(summary["bounded_bytes"], 65536);
        assert_eq!(summary["truncated"], true);
        assert_eq!(summary["has_panic_marker"], true);
        assert_eq!(summary["has_nil_pointer_marker"], true);
        assert_eq!(
            summary["native_function_names_only"],
            json!(["verysync.com/verysync/verysync/lib/model.(*model).Closed"])
        );
        let encoded = summary.to_string();
        for private in [secret, "0xCAFEBABE", "synthetic-private-path"] {
            assert!(!encoded.contains(private));
        }
        Ok(())
    }
}
