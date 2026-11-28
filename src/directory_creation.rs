//! Explicit directory creation in a selected VerySync namespace.

use crate::{
    Error, ManagementWriteEvidence, OperationCompletion, ResourcePath, ResponseDiagnostic, Result,
    StorageEndpoint, TargetPath,
};

/// The target and namespace for one directory operation.
#[non_exhaustive]
pub enum DirectoryTarget<'a> {
    /// A file-manager volume and its exact relative directory.
    FileManager(&'a ResourcePath),
    /// An absolute path on the native directory picker and its local mount.
    NativePicker(&'a TargetPath),
    /// A specific Local Sync backend and the parent-relative name.
    LocalSync {
        /// Selected endpoint, including its explicit authentication when needed.
        endpoint: &'a StorageEndpoint,
        /// Parent directory in the backend's slash-separated namespace.
        parent: &'a str,
        /// One directory name under that parent.
        name: &'a str,
    },
}

/// Original directory creation response and a separate directory check.
#[derive(Debug)]
#[non_exhaustive]
pub struct DirectoryCreationReport {
    /// Dispatch and response evidence for the optional creation request.
    pub write: ManagementWriteEvidence,
    /// Original reply. No reply in a success means the directory already existed.
    pub original: Result<Option<ResponseDiagnostic>>,
    /// Whether this exact directory existed before submission, if observable.
    pub existed_before: Option<bool>,
    /// Whether the exact directory is present in the original namespace.
    pub directory_present: Option<bool>,
    /// Why the selected directory could not be verified after submission.
    pub observation_error: Option<Error>,
}

impl DirectoryCreationReport {
    /// Classify the selected directory, independently of possible parent creation.
    pub fn completion(&self) -> OperationCompletion {
        match self.directory_present {
            Some(true) => OperationCompletion::Completed,
            Some(false) => OperationCompletion::GoalNotMet,
            None if !self.write.dispatched
                || (self.write.response_complete
                    && matches!(
                        self.original,
                        Err(Error::Authentication { .. }
                            | Error::AccessDenied { .. }
                            | Error::LicenseRequired { .. })
                    )) =>
            {
                OperationCompletion::GoalNotMet
            }
            None => OperationCompletion::Unconfirmed,
        }
    }
}
