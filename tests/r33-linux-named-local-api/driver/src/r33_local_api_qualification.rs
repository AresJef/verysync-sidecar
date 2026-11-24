//! Read-only qualification for the LA-012 protected native route.
use verysync_sidecar::{Error, FolderId, LocalApiClient, TargetPath};

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Qualification {
    Eligible,
    ReadbackMismatch { exact_id: bool, exact_path: bool },
    LicenseRequired { code: i64, http: u16 },
    HttpFailure { http: u16 },
    Unconfirmed,
}

pub(crate) async fn observe(
    local: &LocalApiClient,
    id: &FolderId,
    path: &TargetPath,
) -> Qualification {
    match local.folder_configuration(id).await {
        Ok(actual) => {
            let exact_id = &actual.id == id;
            let exact_path = matches!(
                (actual.path.to_protocol(), path.to_protocol()),
                (Ok(actual), Ok(expected)) if actual == expected
            );
            if exact_id && exact_path {
                Qualification::Eligible
            } else {
                Qualification::ReadbackMismatch {
                    exact_id,
                    exact_path,
                }
            }
        }
        Err(Error::LicenseRequired { code, response }) => Qualification::LicenseRequired {
            code,
            http: response.status(),
        },
        Err(Error::AccessDenied { response } | Error::Http { response }) => {
            Qualification::HttpFailure {
                http: response.status(),
            }
        }
        Err(_) => Qualification::Unconfirmed,
    }
}
