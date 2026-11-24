use crate::Stage;
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
};

pub(crate) struct Receipts {
    directory: PathBuf,
}

impl Receipts {
    pub(crate) fn new(root: &Path) -> Self {
        Self {
            directory: root.join("owned-case-receipts"),
        }
    }

    pub(crate) fn valid(&self, request: &str) -> bool {
        (16..=32).contains(&request.len())
            && request.bytes().all(|byte| byte.is_ascii_alphanumeric())
    }

    pub(crate) fn begin(&self, request: &str) -> Stage<()> {
        if !self.valid(request) {
            return Err("owned-case-request-invalid");
        }
        fs::create_dir_all(&self.directory).map_err(|_| "owned-case-receipt-root-failed")?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.directory.join(format!("{request}.submitted")))
            .and_then(|file| file.sync_all())
            .map_err(|_| "owned-case-request-already-submitted-or-unrecordable")
    }

    pub(crate) fn finish(&self, request: &str, report: &Value) -> Stage<()> {
        let scratch = self.directory.join(format!("{request}.partial"));
        let path = self.directory.join(format!("{request}.json"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&scratch)
            .map_err(|_| "owned-case-receipt-create-failed")?;
        serde_json::to_writer(&mut file, report).map_err(|_| "owned-case-receipt-encode-failed")?;
        file.write_all(b"\n")
            .and_then(|()| file.sync_all())
            .map_err(|_| "owned-case-receipt-flush-failed")?;
        fs::rename(scratch, path).map_err(|_| "owned-case-receipt-publish-failed")
    }

    pub(crate) fn read(&self, request: &str) -> Stage<Value> {
        if !self.valid(request) {
            return Err("owned-case-request-invalid");
        }
        let result = self.directory.join(format!("{request}.json"));
        match fs::read(result) {
            Ok(data) => {
                let result: Value =
                    serde_json::from_slice(&data).map_err(|_| "owned-case-receipt-invalid")?;
                Ok(json!({"ok":true,"request":request,"state":"recorded","result":result}))
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let submitted = self
                    .directory
                    .join(format!("{request}.submitted"))
                    .is_file();
                Ok(json!({
                    "ok":true, "request":request,
                    "state": if submitted { "submitted-result-pending" } else { "not-submitted" }
                }))
            }
            Err(_) => Err("owned-case-receipt-unavailable"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Receipts;
    use serde_json::json;
    use std::{
        env, fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn exact_request_is_submitted_once_and_its_result_is_read_only() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!("r33-schedule-receipt-{unique}"));
        fs::create_dir(&root).unwrap();
        let receipts = Receipts::new(&root);
        let request = "fresh00000000001";
        assert!(!receipts.valid("../../user-file"));
        assert_eq!(receipts.read(request).unwrap()["state"], "not-submitted");
        receipts.begin(request).unwrap();
        assert!(receipts.begin(request).is_err());
        assert_eq!(
            receipts.read(request).unwrap()["state"],
            "submitted-result-pending"
        );
        receipts
            .finish(request, &json!({"owned_registration_absent":true}))
            .unwrap();
        assert_eq!(
            receipts.read(request).unwrap()["result"],
            json!({"owned_registration_absent":true})
        );
        fs::remove_dir_all(root).unwrap();
    }
}
