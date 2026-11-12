//! Public value-type contracts; these do not establish engine functionality.

use verysync_sidecar::{EndpointKind, Error, ManagementEndpoint, PathStyle, TargetPath};

#[test]
fn endpoint_classifies_explicit_loopback_and_remote_http_without_discovery() {
    for value in [
        "http://127.0.0.1:53841",
        "https://[::1]:53841",
        "http://localhost:53841",
    ] {
        assert_eq!(
            ManagementEndpoint::http(value).unwrap().kind(),
            EndpointKind::LoopbackTcp
        );
    }
    for value in [
        "http://10.20.30.40:53841",
        "https://synthetic.invalid/prefix",
    ] {
        let endpoint = ManagementEndpoint::http(value).unwrap();
        assert_eq!(endpoint.kind(), EndpointKind::RemoteHttp);
        assert!(endpoint.http_url().unwrap().path().ends_with('/'));
        assert_eq!(endpoint.socket_path(), None);
    }
    assert_eq!(
        ManagementEndpoint::http("https://synthetic.invalid/prefix")
            .unwrap()
            .http_url()
            .unwrap()
            .as_str(),
        "https://synthetic.invalid/prefix/"
    );
}

#[test]
fn endpoint_rejects_credentials_and_ambiguous_url_components_without_echoing_them() {
    for value in [
        "not-an-absolute-url",
        "ftp://synthetic.invalid/",
        "http://user:synthetic-secret@synthetic.invalid/",
        "http://synthetic.invalid/?token=synthetic-secret",
        "http://synthetic.invalid/#synthetic-secret",
        "http://synthetic.invalid:0/",
        "http://synthetic.invalid/\nother",
    ] {
        let error = ManagementEndpoint::http(value).unwrap_err();
        assert!(matches!(error, Error::InvalidEndpoint { .. }));
        assert!(!format!("{error:?} {error}").contains("synthetic-secret"));
    }
}

#[test]
fn endpoint_socket_uses_an_explicit_absolute_native_path() -> Result<(), Box<dyn std::error::Error>>
{
    let native = std::env::current_dir()?
        .join("synthetic-state")
        .join("control.sock");
    let endpoint = ManagementEndpoint::unix_socket(&native)?;
    assert_eq!(endpoint.kind(), EndpointKind::UnixSocket);
    assert_eq!(endpoint.socket_path(), Some(native.as_path()));
    assert_eq!(endpoint.http_url(), None);
    assert!(ManagementEndpoint::unix_socket("relative.sock").is_err());
    assert!(ManagementEndpoint::unix_socket(native.join("bad\0socket")).is_err());
    Ok(())
}

#[test]
fn path_preserves_native_unicode_without_normalizing_filesystem_meaning() {
    let native = std::path::PathBuf::from("synthetic")
        .join("中文 空格")
        .join("..")
        .join("file.txt");
    let path = TargetPath::local(&native);
    assert_eq!(path.local_path(), Some(native.as_path()));
    assert_eq!(path.to_protocol().unwrap(), native.to_str().unwrap());
}

#[test]
fn path_remote_style_is_explicit_and_independent_of_the_host() {
    let windows = r"C:\合成 数据\file.txt";
    let unix = "/synthetic/C:\\literal/../file.txt";
    for (style, value) in [(PathStyle::Windows, windows), (PathStyle::Unix, unix)] {
        let path = TargetPath::remote(style, value).unwrap();
        assert_eq!(path.style(), style);
        assert_eq!(path.to_protocol().unwrap(), value);
        assert_eq!(path.local_path(), None);
    }
}

#[test]
fn path_rejects_empty_or_nul_values_at_the_protocol_boundary() {
    for text in ["", "synthetic\0other"] {
        assert!(matches!(
            TargetPath::remote(PathStyle::Unix, text),
            Err(Error::InvalidPath { .. })
        ));
        assert!(matches!(
            TargetPath::local(text).to_protocol(),
            Err(Error::InvalidPath { .. })
        ));
    }
}

#[cfg(unix)]
#[test]
fn path_retains_non_utf8_native_encoding_but_rejects_lossy_protocol_conversion() {
    use std::os::unix::ffi::OsStringExt;
    let native = std::path::PathBuf::from(std::ffi::OsString::from_vec(vec![b'f', 0xff]));
    let path = TargetPath::local(&native);
    assert_eq!(path.local_path(), Some(native.as_path()));
    assert!(matches!(path.to_protocol(), Err(Error::PathEncoding)));
}

#[cfg(windows)]
#[test]
fn path_rejects_unpaired_native_surrogates_without_replacement() {
    use std::os::windows::ffi::OsStringExt;
    let native = std::ffi::OsString::from_wide(&[b'f' as u16, 0xd800]);
    let path = TargetPath::local(std::path::PathBuf::from(native));
    assert!(matches!(path.to_protocol(), Err(Error::PathEncoding)));
}
