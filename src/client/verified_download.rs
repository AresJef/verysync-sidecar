//! One verified single-file response and an optional exact suffix.

use std::{io, path::Path, time::Duration};

use reqwest::Response;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use super::{transport_error, Client};
use crate::{
    managed::DownloadStaging, operation_options::OperationContext, Error, OperationPhase,
    ResourceByteRange, ResourceChecksum, ResourceDownload, ResourcePath, ResponseDiagnostic,
    Result, VerifiedDownloadOptions, VerifiedDownloadReport, BASELINE_ENGINE_VERSION,
};

const DOWNLOAD: &str = "download the verified single file";
const PUBLISH: &str = "publish the verified download";

#[derive(Clone, Copy, PartialEq, Eq)]
struct SourceVersion {
    bytes: u64,
    sha256: [u8; 32],
}

#[derive(Default)]
struct StagedBytes {
    bytes: u64,
    hash: Sha256,
}

impl Client {
    /// Download one file into a new absolute path and verify it before publication.
    ///
    /// The fixed engine must provide an authenticated SHA-256 for the regular
    /// source file. The SDK verifies the complete local bytes against that
    /// version, and publishes without replacing an existing path. Use trusted
    /// management transport and an existing destination directory that you control.
    ///
    /// With explicit `resume_once`, a partial transport failure can lead to
    /// one exact suffix request. The source version and private local prefix
    /// must still match. The ordinary streaming and archive APIs retain their
    /// original behavior. If a failure leaves staged data, inspect its private
    /// path through the returned report before choosing what to do with it.
    pub async fn download_file_and_verify(
        &self,
        path: &ResourcePath,
        destination: &Path,
        options: VerifiedDownloadOptions,
    ) -> Result<VerifiedDownloadReport> {
        if !destination.is_absolute() || destination.file_name().is_none() || options.max_bytes == 0
        {
            return Err(rejected(
                "a verified download requires an absolute output filename and positive byte bound",
            ));
        }
        if self.instance().version.version != BASELINE_ENGINE_VERSION {
            return Err(rejected(
                "the selected engine version has no verified single-file download contract",
            ));
        }
        let context = options.operation.start()?;
        let mut report = VerifiedDownloadReport {
            completed: None,
            staged_bytes: 0,
            data_requests: 0,
            source_sha256: None,
            resumed_range: None,
            initial_error: None,
            error: None,
            cleanup_error: None,
            partial: None,
            publication_entered: false,
        };
        let mut staged = StagedBytes::default();
        let result = context.wait(context.deadline, DOWNLOAD, async {
            context.phase(OperationPhase::Checking);
            match tokio::fs::symlink_metadata(destination).await {
                Ok(_) => return Err(rejected("the selected output already exists")),
                Err(source) if source.kind() == io::ErrorKind::NotFound => {}
                Err(source) => return Err(local("inspect the selected download destination", source)),
            }
            let version = self.verified_source_version(path).await?;
            if version.bytes > options.max_bytes {
                return Err(rejected("the selected file exceeds the explicit download byte bound"));
            }
            report.source_sha256 = Some(version.sha256);
            if options.expected_sha256.is_some_and(|expected| expected != version.sha256) {
                return Err(rejected("the source SHA-256 differs from the expected version"));
            }
            let (staging, file) = DownloadStaging::allocate(destination)?;
            report.partial = Some(staging.path.clone());
            let mut output = tokio::fs::File::from_std(file);
            let mut response = self.open_verified_stream(path, version, None, &mut report, &context).await?;
            let media_type = response.headers().get("content-type")
                .and_then(|value| value.to_str().ok()).map(str::to_owned);
            let first = stream_into_file(&mut response, &mut output, &mut staged, version.bytes).await;
            if let Err(source) = first {
                if !options.resume || !matches!(source, Error::Transport { .. } | Error::Timeout { .. })
                    || staged.bytes == 0 || staged.bytes >= version.bytes
                {
                    return Err(source);
                }
                report.initial_error = Some(source);
                self.require_same_file_version(path, version).await?;
                output.flush().await.map_err(|source| local("settle the staged prefix", source))?;
                verify_staged_bytes(&mut output, staged.bytes, staged.hash.clone().finalize().into()).await?;
                let range = ResourceByteRange::new(staged.bytes, version.bytes - 1)?;
                let mut suffix = self.open_verified_stream(path, version, Some(range), &mut report, &context).await?;
                stream_into_file(&mut suffix, &mut output, &mut staged, version.bytes).await?;
            }
            output.flush().await.map_err(|source| local("flush the verified download", source))?;
            context.phase(OperationPhase::Verifying);
            if staged.bytes != version.bytes || <[u8; 32]>::from(staged.hash.clone().finalize()) != version.sha256 {
                return Err(rejected("the received file does not match the selected source SHA-256"));
            }
            self.require_same_file_version(path, version).await?;
            let before_read = output.try_clone().await.map_err(|source| local("duplicate the staged file handle", source))?.into_std().await;
            let stamp = staging.file_stamp(&before_read, version.bytes)?;
            verify_staged_bytes(&mut output, version.bytes, version.sha256).await?;
            output.sync_all().await.map_err(|source| local("sync the verified local file", source))?;
            let file = output.into_std().await;
            drop(before_read);
            staging.verify_file_handle(&file, stamp)?;
            if tokio::time::Instant::now() >= context.deadline {
                return Err(Error::Timeout { operation: PUBLISH });
            }
            if context.cancelled_on().is_some_and(|cancel| *cancel.borrow()) {
                return Err(Error::OperationWaitCancelled { operation: PUBLISH });
            }
            report.publication_entered = true;
            if let Err(source) = staging.publish(destination) {
                if matches!(&source, Error::LocalIo { source, .. } if source.kind() == io::ErrorKind::AlreadyExists) {
                    report.publication_entered = false;
                }
                return Err(source);
            }
            drop(file);
            report.completed = Some(ResourceDownload {
                bytes: version.bytes, sha256: version.sha256, media_type, content_range: None,
            });
            let cleanup = staging.cleanup();
            if cleanup.is_ok() {
                report.partial = None;
            }
            report.cleanup_error = cleanup.err();
            Ok(())
        }).await;
        report.staged_bytes = staged.bytes;
        report.error = result.err();
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    async fn verified_source_version(&self, path: &ResourcePath) -> Result<SourceVersion> {
        let algorithm = ResourceChecksum::Sha256;
        let (metadata, status, body) = self.read_resource_metadata(path, Some(algorithm)).await?;
        if metadata.is_dir {
            return Err(rejected("the selected resource is a directory"));
        }
        let sha256 = metadata
            .checksums
            .get(algorithm.name())
            .and_then(|text| decode_sha256(text))
            .ok_or(Error::InvalidResponse {
                operation: "identify the source file by SHA-256",
                response: ResponseDiagnostic::new(status, body),
            })?;
        Ok(SourceVersion {
            bytes: metadata.size,
            sha256,
        })
    }

    async fn require_same_file_version(
        &self,
        path: &ResourcePath,
        expected: SourceVersion,
    ) -> Result<()> {
        if self.verified_source_version(path).await? != expected {
            return Err(rejected("the source file changed during the download"));
        }
        Ok(())
    }

    async fn open_verified_stream(
        &self,
        path: &ResourcePath,
        source: SourceVersion,
        range: Option<ResourceByteRange>,
        report: &mut VerifiedDownloadReport,
        context: &OperationContext,
    ) -> Result<Response> {
        self.system_status().await?;
        let mut url = self.resource_url("rest/f/api/raw", path)?;
        url.query_pairs_mut().append_pair("algo", "none");
        let remaining = context
            .deadline
            .saturating_duration_since(tokio::time::Instant::now());
        if remaining < Duration::from_millis(1) {
            return Err(Error::Timeout {
                operation: DOWNLOAD,
            });
        }
        let mut request = self
            .connection
            .authorized_request(reqwest::Method::GET, url, None)
            .timeout(remaining);
        if let Some(range) = range {
            request = request.header("Range", format!("bytes={}-{}", range.first(), range.last()));
        }
        report.data_requests += 1;
        report.resumed_range = range;
        let mut response = request
            .send()
            .await
            .map_err(|source| transport_error(DOWNLOAD, source))?;
        if !response.status().is_success() {
            return Err(
                read_refused_download(&mut response, self.connection.response_limit).await?,
            );
        }
        let content_range = response
            .headers()
            .get("content-range")
            .and_then(|value| value.to_str().ok());
        let allowed_length = if let Some(range) = range {
            let exact = format!("bytes {}-{}/{}", range.first(), range.last(), source.bytes);
            if response.status() != reqwest::StatusCode::PARTIAL_CONTENT
                || content_range != Some(exact.as_str())
            {
                return Err(rejected(
                    "the source did not return the exact verified suffix",
                ));
            }
            range.last() - range.first() + 1
        } else {
            if response.status() != reqwest::StatusCode::OK
                || response.headers().contains_key("content-range")
            {
                return Err(rejected(
                    "the source did not return a complete single-file response",
                ));
            }
            source.bytes
        };
        if response
            .content_length()
            .is_some_and(|length| length != allowed_length)
        {
            return Err(rejected(
                "the response length differs from the verified file interval",
            ));
        }
        Ok(response)
    }
}

async fn read_refused_download(response: &mut Response, limit: usize) -> Result<Error> {
    let status = response.status().as_u16();
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|source| transport_error(DOWNLOAD, source))?
    {
        if chunk.len() > limit.saturating_sub(bytes.len()) {
            return Err(Error::ResponseTooLarge { limit });
        }
        bytes.extend_from_slice(&chunk);
    }
    let response = ResponseDiagnostic::new(status, bytes);
    Ok(match status {
        401 => Error::Authentication { status },
        403 => Error::AccessDenied { response },
        _ => Error::Http { response },
    })
}

async fn stream_into_file(
    response: &mut Response,
    output: &mut tokio::fs::File,
    staged: &mut StagedBytes,
    total: u64,
) -> Result<()> {
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|source| transport_error(DOWNLOAD, source))?
    {
        if chunk.len() as u64 > total.saturating_sub(staged.bytes) {
            return Err(rejected(
                "the source sent more bytes than the verified file interval",
            ));
        }
        for block in chunk.chunks(65536) {
            output
                .write_all(block)
                .await
                .map_err(|source| local("write the staged file", source))?;
            staged.bytes += block.len() as u64;
            staged.hash.update(block);
        }
    }
    if staged.bytes != total {
        return Err(rejected(
            "the source closed before returning the verified file interval",
        ));
    }
    Ok(())
}

async fn verify_staged_bytes(
    output: &mut tokio::fs::File,
    expected_bytes: u64,
    expected_sha256: [u8; 32],
) -> Result<()> {
    let metadata = output
        .metadata()
        .await
        .map_err(|source| local("inspect the staged download", source))?;
    if metadata.len() != expected_bytes {
        return Err(rejected("the local staged file length changed"));
    }
    output
        .seek(io::SeekFrom::Start(0))
        .await
        .map_err(|source| local("rewind the staged download", source))?;
    let mut bytes_left = expected_bytes;
    let mut block = vec![0; 65536];
    let mut hash = Sha256::new();
    while bytes_left != 0 {
        let read = bytes_left.min(block.len() as u64) as usize;
        output
            .read_exact(&mut block[..read])
            .await
            .map_err(|source| local("read the staged file independently", source))?;
        hash.update(&block[..read]);
        bytes_left -= read as u64;
    }
    if <[u8; 32]>::from(hash.finalize()) != expected_sha256 {
        return Err(rejected("the local staged file SHA-256 changed"));
    }
    Ok(())
}

fn decode_sha256(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.is_ascii() {
        return None;
    }
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(digest)
}

fn rejected(reason: &'static str) -> Error {
    Error::ResourceTransferRejected { reason }
}

fn local(operation: &'static str, source: io::Error) -> Error {
    Error::LocalIo { operation, source }
}
