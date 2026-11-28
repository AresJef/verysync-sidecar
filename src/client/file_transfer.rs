//! Payload streaming with explicit local destinations and finite bounds.
use super::{
    mutation_error, transport_error, verified_download::decode_sha256, workflow_write_result,
    Client,
};
use crate::{
    Error, OperationOptions, OperationPhase, ResourceArchiveFormat, ResourceByteRange,
    ResourceChecksum, ResourceDownload, ResourcePath, ResourceTransferOptions, ResourceUpload,
    ResourceUploadConflict, ResponseDiagnostic, Result, TargetPath, VerifiedUploadOutcome,
    VerifiedUploadReport,
};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

impl Client {
    /// Stream a remote file (or explicitly selected finite range) into a NEW
    /// absolute local file. Existing files/symlinks are refused by create_new;
    /// no Content-Disposition filename is used. Partial output is retained on
    /// failure/cancellation; inspect or remove that exact destination yourself.
    /// With the fixed engine, a complete download disables directory archiving
    /// on the streaming request itself. Use the explicit archive methods for
    /// directories or selections.
    /// A pending Tokio filesystem write may finish after this future is dropped.
    pub async fn download_resource(
        &self,
        path: &ResourcePath,
        destination: &Path,
        range: Option<ResourceByteRange>,
        options: &ResourceTransferOptions,
    ) -> Result<ResourceDownload> {
        options.validate()?;
        validate_destination(destination)?;
        let mut url = self.resource_url("rest/f/api/raw", path)?;
        if range.is_none() {
            // In v2.33.2 the directory branch validates the archive algorithm
            // before building an archive. The file branch streams the resolved
            // object without consulting it, including an empty regular file.
            url.query_pairs_mut().append_pair("algo", "none");
        }
        self.download_resource_url(url, destination, range, None, options)
            .await
    }

    /// Ask the engine to archive an explicit directory, then stream the archive
    /// to a NEW absolute local file. No SDK extraction or filename choice occurs.
    /// Limits/deadlines and retained partial outputs match download_resource.
    pub async fn download_resource_archive(
        &self,
        path: &ResourcePath,
        format: ResourceArchiveFormat,
        destination: &Path,
        options: &ResourceTransferOptions,
    ) -> Result<ResourceDownload> {
        options.validate()?;
        validate_destination(destination)?;
        let mut url = self.resource_url("rest/f/api/raw", path)?;
        url.query_pairs_mut().append_pair("algo", format.name());
        within(options.deadline, "download resource archive", async {
            if !self.resource_info(path).await?.is_dir {
                return Err(rejected("archive input must be a directory"));
            }
            self.download_resource_url(url, destination, None, Some(format), options)
                .await
        })
        .await
    }

    /// Archive 1..=1024 relative resources within one explicit base directory.
    /// All paths use the target syntax. Each volume-relative resource URI is
    /// escaped before the comma-separated selection is encoded as a query value;
    /// literal comma, percent, Unicode and Unix control filenames stay data.
    /// No local path is constructed from returned archive entry names.
    pub async fn download_selected_resources(
        &self,
        base: &ResourcePath,
        selected: &[TargetPath],
        format: ResourceArchiveFormat,
        destination: &Path,
        options: &ResourceTransferOptions,
    ) -> Result<ResourceDownload> {
        options.validate()?;
        validate_destination(destination)?;
        if selected.is_empty() || selected.len() > 1024 {
            return Err(rejected(
                "archive selection must contain 1 to 1024 resources",
            ));
        }
        let root = ResourcePath::root(base.volume.clone(), base.style);
        let mut url = self.resource_url("rest/f/api/raw", &root)?;
        let root_prefix = url.path().to_owned();
        let mut names = Vec::with_capacity(selected.len());
        let mut selected_bytes = 0usize;
        for selected_path in selected {
            if selected_path.to_protocol()?.len() > 64 * 1024 {
                return Err(rejected("selected path exceeds the selection byte bound"));
            }
            let relative = ResourcePath::relative(base.volume.clone(), selected_path)?;
            if relative.style != base.style {
                return Err(rejected("archive selection syntax differs from its base"));
            }
            let mut full = base.clone();
            for part in relative.components {
                full = full.child(part)?;
            }
            let encoded = self.resource_url("rest/f/api/raw", &full)?;
            let name = encoded
                .path()
                .strip_prefix(&root_prefix)
                .ok_or_else(|| rejected("selected URI escaped its volume root"))?
                .to_owned();
            selected_bytes = selected_bytes.saturating_add(name.len() + 1);
            if selected_bytes > 64 * 1024 {
                return Err(rejected("encoded archive selection exceeds the URL bound"));
            }
            if names.contains(&name) {
                return Err(rejected("archive selection contains a duplicate"));
            }
            names.push(name);
        }
        // The fixed native endpoint resolves files from the VOLUME root. It
        // does not interpret the selection relative to the requested base URL.
        url.query_pairs_mut()
            .append_pair("files", &names.join(","))
            .append_pair("algo", format.name());
        within(options.deadline, "download selected resources", async {
            if !self.resource_info(base).await?.is_dir {
                return Err(rejected("archive selection base must be a directory"));
            }
            self.download_resource_url(url, destination, None, Some(format), options)
                .await
        })
        .await
    }

    async fn download_resource_url(
        &self,
        url: url::Url,
        destination: &Path,
        range: Option<ResourceByteRange>,
        archive: Option<ResourceArchiveFormat>,
        options: &ResourceTransferOptions,
    ) -> Result<ResourceDownload> {
        let operation = "download file resource";
        within(options.deadline, operation, async {
            self.system_status().await?;
            let mut request = self
                .connection
                .http
                .get(url)
                .header("X-API-Key", self.connection.key.header())
                .timeout(options.deadline);
            if let Some(range) = range {
                request = request.header("Range", format!("bytes={}-{}", range.first, range.last));
            }
            let mut response = request
                .send()
                .await
                .map_err(|e| transport_error(operation, e))?;
            let status = response.status().as_u16();
            if !(200..300).contains(&status) {
                let mut bytes = Vec::new();
                while let Some(chunk) = response
                    .chunk()
                    .await
                    .map_err(|e| transport_error(operation, e))?
                {
                    if chunk.len() > self.connection.response_limit.saturating_sub(bytes.len()) {
                        return Err(Error::ResponseTooLarge {
                            limit: self.connection.response_limit,
                        });
                    }
                    bytes.extend_from_slice(&chunk);
                }
                return Err(match status {
                    401 => Error::Authentication { status },
                    403 => Error::AccessDenied {
                        response: ResponseDiagnostic::new(status, bytes),
                    },
                    _ => Error::Http {
                        response: ResponseDiagnostic::new(status, bytes),
                    },
                });
            }
            let media_type = response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let content_range = response
                .headers()
                .get("content-range")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let expected = match range {
                Some(range) => {
                    let prefix = format!("bytes {}-{}/", range.first, range.last);
                    let total = content_range
                        .as_deref()
                        .and_then(|value| value.strip_prefix(&prefix))
                        .and_then(|value| value.parse::<u64>().ok());
                    if status != 206 || !total.is_some_and(|total| total > range.last) {
                        return Err(rejected(
                            "server did not return the exact requested byte interval",
                        ));
                    }
                    Some(range.last - range.first + 1)
                }
                None if status == 200
                    && (archive.is_some() || !response.headers().contains_key("content-range")) =>
                {
                    response.content_length()
                }
                None => return Err(rejected("unexpected partial resource response")),
            };
            if let Some(format) = archive {
                if media_type.as_deref().is_none_or(|m| {
                    !m.split(';')
                        .next()
                        .is_some_and(|v| v.trim().eq_ignore_ascii_case(format.media_type()))
                }) {
                    return Err(rejected(
                        "server did not return the selected native archive media type",
                    ));
                }
            }
            if expected.is_some_and(|bytes| bytes > options.max_bytes) {
                return Err(rejected(
                    "resource exceeds the explicit transfer byte bound",
                ));
            }
            if range.is_some()
                && response
                    .content_length()
                    .is_some_and(|length| Some(length) != expected)
            {
                return Err(rejected(
                    "Content-Length contradicts the requested byte interval",
                ));
            }
            let mut output = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)
                .await
                .map_err(|e| local("create new resource output", e))?;
            let mut bytes = 0u64;
            let mut hash = Sha256::new();
            let received = async {
                while let Some(chunk) = response
                    .chunk()
                    .await
                    .map_err(|e| transport_error(operation, e))?
                {
                    if chunk.len() as u64 > options.max_bytes.saturating_sub(bytes) {
                        return Err(rejected(
                            "resource exceeded the explicit transfer byte bound",
                        ));
                    }
                    for block in chunk.chunks(65536) {
                        output
                            .write_all(block)
                            .await
                            .map_err(|e| local("write resource output", e))?;
                        bytes += block.len() as u64;
                        hash.update(block);
                    }
                }
                if expected.is_some_and(|length| length != bytes) {
                    return Err(rejected(
                        "resource body length differs from the announced interval",
                    ));
                }
                Ok::<(), Error>(())
            }
            .await;
            // Tokio file writes can still be pending after write_all returns.
            // Ordinary receive failures settle accepted writes before returning.
            // A deadline/cancel can interrupt this flush and retains that caveat.
            output
                .flush()
                .await
                .map_err(|e| local("flush resource output", e))?;
            received?;
            Ok(ResourceDownload {
                bytes,
                sha256: hash.finalize().into(),
                media_type,
                content_range,
            })
        })
        .await
    }

    /// Stream a regular, non-symlink local file once. Hash the complete input
    /// before POST, then verify the remote SHA-256 after the known acknowledgement.
    /// Keep the input immutable throughout. No automatic retry/cleanup occurs;
    /// cancellation or an error after POST can leave a partial/replaced target.
    /// RejectExisting delegates conflict refusal to the kernel, without claiming
    /// an atomic transaction against other writers. Local input is never changed.
    pub async fn upload_resource(
        &self,
        path: &ResourcePath,
        source: &Path,
        conflict: ResourceUploadConflict,
        options: &ResourceTransferOptions,
    ) -> Result<ResourceUpload> {
        options.validate()?;
        if !source.is_absolute() {
            return Err(rejected("upload source must be an absolute local path"));
        }
        if path.components.is_empty() {
            return Err(rejected("an upload must name a file within its volume"));
        }
        let mut url = self.resource_url("rest/f/api/resources", path)?;
        url.query_pairs_mut().append_pair(
            "override",
            match conflict {
                ResourceUploadConflict::RejectExisting => "false",
                ResourceUploadConflict::Replace => "true",
            },
        );
        let operation = "upload file resource";
        let mut attempted = false;
        // The outer deadline also covers input hashing and post-upload checksum.
        // It does not imply rollback or that the server stopped writing on cancel.
        within(options.deadline, operation, async {
            let _guard = self.connection.mutation_lock.lock().await;
            self.system_status().await?;
            let input = prepare_upload(source, options.max_bytes).await?;
            let total = input.bytes;
            let sha256 = input.sha256;
            let request = self
                .connection
                .http
                .post(url)
                .header("X-API-Key", self.connection.key.header())
                .header("Content-Type", "application/octet-stream")
                .header("Content-Length", total)
                .timeout(options.deadline)
                .body(input.stream());
            attempted = true;
            let (status, body) = self
                .connection
                .request_prepared(operation, request, true)
                .await?;
            if body != b"200 OK\n" {
                return Err(mutation_error(
                    operation,
                    true,
                    Error::InvalidResponse {
                        operation,
                        response: ResponseDiagnostic::new(status, body),
                    },
                ));
            }
            let remote = self
                .resource_checksum(path, ResourceChecksum::Sha256)
                .await
                .map_err(|e| mutation_error(operation, true, e))?;
            let expected = sha256
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            if !remote.eq_ignore_ascii_case(&expected) {
                return Err(mutation_error(
                    operation,
                    true,
                    rejected("uploaded remote digest differs from the complete local input"),
                ));
            }
            Ok(ResourceUpload {
                bytes: total,
                sha256,
            })
        })
        .await
        .map_err(|e| match e {
            Error::Timeout { .. } if attempted => mutation_error(operation, true, e),
            other => other,
        })
    }

    /// Upload one dedicated local file and verify the selected remote
    /// destination within a single operation deadline. With `Replace` an
    /// exact existing match needs no write. With `RejectExisting` a current
    /// destination is refused, and the native conflict check remains active
    /// during upload. The SDK never repeats a write after an uncertain reply.
    ///
    /// Keep the input immutable until the operation returns, and coordinate
    /// other writers to this destination. Readback proves the observed bytes,
    /// including when the original acknowledgement remains unknown.
    pub async fn upload_file_and_verify(
        &self,
        path: &ResourcePath,
        source: &Path,
        conflict: ResourceUploadConflict,
        max_bytes: u64,
        options: OperationOptions,
    ) -> Result<VerifiedUploadReport> {
        const UPLOAD: &str = "upload the selected local file";
        const CHECK: &str = "check the uploaded destination";
        use VerifiedUploadOutcome as Outcome;
        if !source.is_absolute() || path.components.is_empty() || max_bytes == 0 {
            return Err(rejected("a verified upload requires an absolute local file, a destination filename and a positive byte bound"));
        }
        if self.instance().version.version != crate::BASELINE_ENGINE_VERSION {
            return Err(rejected(
                "the selected engine version has no verified upload contract",
            ));
        }
        let mut url = self.resource_url("rest/f/api/resources", path)?;
        url.query_pairs_mut().append_pair(
            "override",
            if conflict == ResourceUploadConflict::Replace {
                "true"
            } else {
                "false"
            },
        );
        let context = options.start()?;
        let deadline = context.dispatch_deadline();
        let mut report = VerifiedUploadReport {
            outcome: Outcome::NotSubmitted,
            write: Default::default(),
            original: None,
            input: None,
            observed: None,
            observation_error: None,
        };
        let mut guard = None;
        let attempt = context
            .wait(deadline, UPLOAD, async {
                context.phase(OperationPhase::Checking);
                guard = Some(self.connection.mutation_lock.lock().await);
                let input = prepare_upload(source, max_bytes).await?;
                let expected = ResourceUpload {
                    bytes: input.bytes,
                    sha256: input.sha256,
                };
                report.input = Some(expected.clone());
                match self.read_upload_target(path).await? {
                    ObservedUploadTarget::Absent => {}
                    _ if conflict == ResourceUploadConflict::RejectExisting => {
                        return Err(Error::ResourceAlreadyExists)
                    }
                    ObservedUploadTarget::Directory => {
                        return Err(rejected("the selected upload destination is a directory"))
                    }
                    ObservedUploadTarget::File(current) if same_upload(&current, &expected) => {
                        report.observed = Some(current);
                        return Ok(false);
                    }
                    ObservedUploadTarget::File(_) => {}
                }
                self.system_status().await?;
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining < Duration::from_millis(1) {
                    return Err(Error::Timeout { operation: UPLOAD });
                }
                let request = self
                    .connection
                    .authorized_request(reqwest::Method::POST, url, None)
                    .header("Content-Type", "application/octet-stream")
                    .header("Content-Length", expected.bytes)
                    .timeout(remaining)
                    .body(input.stream());
                let response = self
                    .connection
                    .send_workflow_write(UPLOAD, request, &context, &mut report.write)
                    .await?;
                if response.body != b"200 OK\n" {
                    return Err(mutation_error(
                        UPLOAD,
                        true,
                        Error::InvalidResponse {
                            operation: UPLOAD,
                            response: ResponseDiagnostic::new(response.status, response.body),
                        },
                    ));
                }
                Ok(true)
            })
            .await;
        if matches!(attempt, Ok(false)) {
            report.outcome = Outcome::AlreadyMatches;
        } else {
            report.original = Some(workflow_write_result(
                UPLOAD,
                report.write,
                attempt.map(|_| ()),
            ));
            if report.write.response_complete
                && matches!(
                    report.original,
                    Some(Err(
                        Error::Authentication { .. } | Error::AccessDenied { .. }
                    ))
                )
            {
                report.outcome = Outcome::Rejected;
            } else if report.write.dispatched {
                context.phase(OperationPhase::Verifying);
                match context
                    .wait(context.deadline, CHECK, self.read_upload_target(path))
                    .await
                {
                    Ok(ObservedUploadTarget::Absent) => report.outcome = Outcome::CurrentAbsent,
                    Ok(ObservedUploadTarget::Directory) => report.outcome = Outcome::CurrentDiffers,
                    Ok(ObservedUploadTarget::File(current)) => {
                        report.outcome = if report
                            .input
                            .as_ref()
                            .is_some_and(|expected| same_upload(&current, expected))
                        {
                            Outcome::CurrentMatches
                        } else {
                            Outcome::CurrentDiffers
                        };
                        report.observed = Some(current);
                    }
                    Err(source) => {
                        report.outcome = Outcome::Unconfirmed;
                        report.observation_error = Some(source);
                    }
                }
            }
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    async fn read_upload_target(&self, path: &ResourcePath) -> Result<ObservedUploadTarget> {
        let algorithm = ResourceChecksum::Sha256;
        let (info, status, body) = match self.read_resource_metadata(path, Some(algorithm)).await {
            Ok(response) => response,
            Err(Error::Http { response }) if response.status() == 404 => {
                return Ok(ObservedUploadTarget::Absent)
            }
            Err(source) => return Err(source),
        };
        if info.is_dir {
            return Ok(ObservedUploadTarget::Directory);
        }
        let sha256 = info
            .checksums
            .get(algorithm.name())
            .and_then(|value| decode_sha256(value))
            .ok_or(Error::InvalidResponse {
                operation: "read the destination SHA-256",
                response: ResponseDiagnostic::new(status, body),
            })?;
        Ok(ObservedUploadTarget::File(ResourceUpload {
            bytes: info.size,
            sha256,
        }))
    }
}

enum ObservedUploadTarget {
    Absent,
    Directory,
    File(ResourceUpload),
}

fn same_upload(a: &ResourceUpload, b: &ResourceUpload) -> bool {
    a.bytes == b.bytes && a.sha256 == b.sha256
}
struct PreparedUpload {
    input: tokio::fs::File,
    bytes: u64,
    sha256: [u8; 32],
}

impl PreparedUpload {
    fn stream(self) -> reqwest::Body {
        reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::with_capacity(
            self.input.take(self.bytes),
            65536,
        ))
    }
}

async fn prepare_upload(source: &Path, max_bytes: u64) -> Result<PreparedUpload> {
    let mut open = tokio::fs::OpenOptions::new();
    open.read(true);
    #[cfg(unix)]
    {
        open.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        open.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut input = open
        .open(source)
        .await
        .map_err(|e| local("open upload input", e))?;
    let metadata = input
        .metadata()
        .await
        .map_err(|e| local("inspect upload input", e))?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(rejected(
            "upload input is not a regular file within the byte bound",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(rejected("upload input is a reparse point"));
        }
    }
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = vec![0; 65536];
    loop {
        let count = input
            .read(&mut buffer)
            .await
            .map_err(|e| local("hash upload input", e))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| rejected("upload size overflow"))?;
        if total > max_bytes {
            return Err(rejected("upload input grew beyond the byte bound"));
        }
        hash.update(&buffer[..count]);
    }
    if total != metadata.len() {
        return Err(rejected("upload input changed length during preparation"));
    }
    let sha256: [u8; 32] = hash.finalize().into();
    input
        .rewind()
        .await
        .map_err(|e| local("rewind upload input", e))?;
    Ok(PreparedUpload {
        input,
        bytes: total,
        sha256,
    })
}

fn validate_destination(path: &Path) -> Result<()> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(rejected("download output must be an absolute local path"))
    }
}
fn rejected(reason: &'static str) -> Error {
    Error::ResourceTransferRejected { reason }
}
fn local(operation: &'static str, source: std::io::Error) -> Error {
    Error::LocalIo { operation, source }
}
async fn within<T>(
    deadline: Duration,
    operation: &'static str,
    future: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(deadline, future)
        .await
        .map_err(|_| Error::Timeout { operation })?
}
