//! Resource decoding never executes JavaScript or treats HTML as a QR image.
use super::*;
fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}
fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}
fn bytes(body: Vec<u8>, media: &str) -> Reply {
    Reply {
        status: 200,
        body,
        headers: format!("Content-Type: {media}\r\n"),
        delay: Duration::ZERO,
    }
}
fn metadata(id: &str) -> Vec<u8> {
    format!("var metadata = {};",serde_json::json!({"authenticated":true,"deviceID":id,"deviceIDShort":"AAAAAAA","isAuthEnabled":true,"futurePrivate":KEY})).into_bytes()
}
// Only a synthetic PNG signature/IHDR contract, not a decodable-image fixture.
fn png() -> Vec<u8> {
    let mut b = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
    b.extend_from_slice(&2u32.to_be_bytes());
    b.extend_from_slice(&3u32.to_be_bytes());
    b.resize(33, 0);
    b
}

#[tokio::test]
async fn gui_resources_use_prefix_headers_trailing_separator_and_exact_text_encoding() -> TestResult
{
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(serde_json::json!(["fr-fr", "en"])),
        identity(),
        bytes(metadata(ID), "application/javascript"),
        identity(),
        bytes(png(), "image/png; synthetic=true"),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert_eq!(
        client
            .native_preferred_languages("en;q=0.2, fr-FR;q=0.9")
            .await?,
        vec!["fr-fr", "en"]
    );
    let m = client.native_gui_metadata().await?;
    assert_eq!(m.device_id.as_str(), ID);
    assert_eq!(m.extra["futurePrivate"], KEY);
    assert!(!format!("{m:?}").contains(KEY));
    let text = format!("QR & + % ? # 测试 {KEY}");
    let qr = client.native_qr_code(&text).await?;
    assert_eq!((qr.width, qr.height), (2, 3));
    assert_eq!(qr.png_bytes(), png());
    assert!(!format!("{qr:?}").contains(KEY));
    let r = server.finish().await?;
    assert_eq!(r.len(), 8);
    assert!(r[3].starts_with("GET /prefix/rest/svc/lang "));
    assert!(r[3]
        .to_lowercase()
        .contains("accept-language: en;q=0.2, fr-fr;q=0.9\r\n"));
    assert!(r[5].starts_with("GET /prefix/meta.js "));
    let target = r[7].split_whitespace().nth(1).ok_or("target absent")?;
    let url = url::Url::parse(&format!("http://synthetic.invalid{target}"))?;
    assert_eq!(url.path(), "/prefix/qr/");
    assert_eq!(
        url.query_pairs().collect::<Vec<_>>(),
        vec![("text".into(), text.into())]
    );
    Ok(())
}

#[tokio::test]
async fn gui_metadata_refuses_script_execution_malformed_schema_and_mismatched_identity(
) -> TestResult {
    let other = ID.replacen('A', "B", 1);
    for (body, mismatch) in [
        (metadata(&other), true),
        (b"var metadata = {};".to_vec(), false),
        (
            [metadata(ID), format!(" evil({KEY});").into_bytes()].concat(),
            false,
        ),
        (
            format!("window.metadata = {{\"secret\":\"{KEY}\"}};").into_bytes(),
            false,
        ),
        (
            metadata(ID)
                .iter()
                .copied()
                .map(|b| if b == b';' { 0xff } else { b })
                .collect(),
            false,
        ),
    ] {
        let server = ScriptedServer::start(vec![
            version(),
            identity(),
            identity(),
            bytes(body, "application/javascript"),
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        let e = client.native_gui_metadata().await.unwrap_err();
        assert!(if mismatch {
            matches!(e, Error::IdentityMismatch { .. })
        } else {
            matches!(e, Error::InvalidResponse { .. })
        });
        assert!(!format!("{e:?}").contains(KEY));
        assert_eq!(server.finish().await?.len(), 4);
    }
    Ok(())
}

#[tokio::test]
async fn gui_resource_invalid_media_headers_or_images_and_inputs_do_not_become_success(
) -> TestResult {
    let mut zero = png();
    zero[16..20].fill(0);
    for (body, media) in [
        (png(), "text/html"),
        (KEY.as_bytes().to_vec(), "image/png"),
        (png()[..24].to_vec(), "image/png"),
        (zero, "image/png"),
    ] {
        let server =
            ScriptedServer::start(vec![version(), identity(), identity(), bytes(body, media)])
                .await?;
        let client = Client::connect(server.options()?).await?;
        let e = client.native_qr_code("synthetic").await.unwrap_err();
        assert!(matches!(e, Error::InvalidResponse { .. }));
        assert!(!format!("{e:?}").contains(KEY));
        assert_eq!(server.finish().await?.len(), 4);
    }
    let server = ScriptedServer::start(vec![version(), identity()]).await?;
    let client = Client::connect(server.options()?).await?;
    assert!(client
        .native_preferred_languages("en\r\nx-injected: value")
        .await
        .is_err());
    assert!(client
        .native_preferred_languages(&"a".repeat(8193))
        .await
        .is_err());
    assert!(client.native_qr_code(&"a".repeat(4097)).await.is_err());
    assert_eq!(server.finish().await?.len(), 2);
    Ok(())
}
