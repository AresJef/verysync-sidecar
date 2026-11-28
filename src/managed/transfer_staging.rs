//! Native private local staging for a single authenticated file download.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use super::native;
use crate::{Error, Result};

pub(crate) struct DownloadStaging {
    pub(crate) path: PathBuf,
    directory: PathBuf,
}

pub(crate) struct StagedFileStamp(native::FileStamp);

impl DownloadStaging {
    pub(crate) fn allocate(destination: &Path) -> Result<(Self, fs::File)> {
        let parent = destination.parent().ok_or(Error::InvalidPath {
            reason: "the download destination must name a file within an existing directory",
        })?;
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|_| Error::ManagedFailure {
            reason: "could not create a private transfer identifier",
        })?;
        let name = id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let directory = parent.join(format!(".verysync-download-{name}"));
        native::create_directory(&directory)
            .map_err(|source| local("create the private download directory", source))?;
        let path = directory.join("download.part");
        let file = match native::create_private(&path) {
            Ok(file) => file,
            Err(source) => {
                let _ = fs::remove_dir(&directory);
                return Err(local("create the private download file", source));
            }
        };
        Ok((Self { path, directory }, file))
    }

    pub(crate) fn file_stamp(&self, file: &fs::File, bytes: u64) -> Result<StagedFileStamp> {
        let stamp = native::observed_file_stamp(file)
            .map_err(|source| local("inspect the staged download handle", source))?;
        if stamp.bytes != bytes || stamp.links != 1 {
            return Err(Error::ResourceTransferRejected {
                reason: "the private download file changed before verification",
            });
        }
        Ok(StagedFileStamp(stamp))
    }

    pub(crate) fn verify_file_handle(
        &self,
        file: &fs::File,
        expected: StagedFileStamp,
    ) -> Result<()> {
        let opened = native::open_private(&self.path, true)
            .map_err(|source| local("reopen the private staged download", source))?;
        let original = native::observed_file_stamp(file)
            .map_err(|source| local("inspect the staged download handle", source))?;
        let current = native::observed_file_stamp(&opened)
            .map_err(|source| local("inspect the staged download path", source))?;
        if original != current || current != expected.0 {
            return Err(Error::ResourceTransferRejected {
                reason: "the private download file changed before publication",
            });
        }
        Ok(())
    }

    pub(crate) fn publish(&self, destination: &Path) -> Result<()> {
        fs::hard_link(&self.path, destination).map_err(|source| {
            local(
                "publish the verified download without replacing a file",
                source,
            )
        })
    }

    pub(crate) fn cleanup(self) -> Result<()> {
        fs::remove_file(&self.path)
            .map_err(|source| local("remove private download staging", source))?;
        fs::remove_dir(&self.directory)
            .map_err(|source| local("remove the private download directory", source))
    }
}

fn local(operation: &'static str, source: io::Error) -> Error {
    Error::LocalIo { operation, source }
}
