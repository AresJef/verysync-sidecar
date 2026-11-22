use super::*;

#[tokio::test]
async fn public_full_download_rejects_directories_and_preserves_explicit_archives() -> TestResult {
    let temp = tempfile::Builder::new().prefix("vfile-").tempdir()?;
    let mut core = ManagedInstance::start(options(&temp.path().join("c"))?).await?;
    let observation: TestResult = async {
        let (profile, volume, relative_base) = mount(&core).await?;
        let output_root = temp.path().to_path_buf();
        let client = core.client().clone();

        // Keep shutdown in the parent even if an assertion or file operation fails.
        tokio::spawn(async move {
            use verysync_sidecar::{Client, ConnectOptions};

            const MANAGEMENT_LIMIT: usize = 16 * 1024;
            let limits = ResourceTransferOptions {
                max_bytes: 3 * 1024 * 1024,
                deadline: Duration::from_secs(20),
            };
            let client = Client::connect(
                ConnectOptions::new(
                    client.endpoint().clone(),
                    client.gui_authentication().await?.api_key()?,
                )
                .expected_device_id(client.instance().device_id.clone())
                .response_limit(MANAGEMENT_LIMIT)?,
            )
            .await?;
            std::fs::create_dir(profile.join("batch"))?;
            std::fs::create_dir(profile.join("empty-dir"))?;
            for (name, data) in [
                ("first.txt", b"first".as_slice()),
                ("second.txt", b"second".as_slice()),
            ] {
                std::fs::write(profile.join("batch").join(name), data)?;
            }
            let batch = volume.clone().child("batch")?;
            let directory_archive = output_root.join("directory.zip");
            let directory_receipt = client
                .download_resource_archive(
                    &batch,
                    ResourceArchiveFormat::Zip,
                    &directory_archive,
                    &limits,
                )
                .await?;
            let zip = std::fs::read(&directory_archive)?;
            assert_eq!(directory_receipt.bytes, zip.len() as u64);
            assert_eq!(directory_receipt.sha256, digest(&zip));
            assert_directory_payloads(zip_contents(&directory_archive)?, &relative_base);

            let selected = output_root.join("selected.zip");
            let selected_receipt = client
                .download_selected_resources(
                    &volume,
                    &[TargetPath::local(Path::new("batch").join("first.txt"))],
                    ResourceArchiveFormat::Zip,
                    &selected,
                    &limits,
                )
                .await?;
            let selected_zip = std::fs::read(&selected)?;
            assert_eq!(selected_receipt.bytes, selected_zip.len() as u64);
            assert_eq!(selected_receipt.sha256, digest(&selected_zip));
            assert_eq!(
                zip_contents(&selected)?,
                BTreeMap::from([(
                    archive_key(&relative_base.join("batch").join("first.txt")),
                    b"first".to_vec(),
                )])
            );

            let text = b"ordinary fixed-engine file";
            let large = vec![b'x'; 64 * 1024 + 17];
            let larger = vec![b'y'; 2 * 1024 * 1024 + 17];
            for (name, fixture) in [
                ("batch.zip", zip.as_slice()),
                ("plain.txt", text.as_slice()),
                ("zero.txt", b"".as_slice()),
                ("large.txt", large.as_slice()),
                ("larger.txt", larger.as_slice()),
            ] {
                std::fs::write(profile.join(name), fixture)?;
                let item = volume.clone().child(name)?;
                let output = output_root.join(format!("received-{name}"));
                let receipt = client
                    .download_resource(&item, &output, None, &limits)
                    .await?;
                assert_eq!(receipt.content_range(), None, "{name}");
                assert_eq!(receipt.bytes, fixture.len() as u64, "{name}");
                assert_eq!(receipt.sha256, digest(fixture), "{name}");
                assert!(std::fs::read(output)? == fixture, "{name} bytes differ");
            }

            let file = volume.clone().child("plain.txt")?;
            let output = output_root.join("range.bin");
            let range = client
                .download_resource(
                    &file,
                    &output,
                    Some(ResourceByteRange::new(2, 8)?),
                    &limits,
                )
                .await?;
            assert_eq!(range.bytes, 7);
            assert_eq!(range.sha256, digest(&text[2..=8]));
            assert_eq!(std::fs::read(output)?, text[2..=8]);
            let expected_content_range = format!("bytes 2-8/{}", text.len());
            assert_eq!(range.content_range(), Some(expected_content_range.as_str()));

            let sentinel_path = output_root.join("existing.bin");
            let sentinel = b"existing output must remain";
            std::fs::write(&sentinel_path, sentinel)?;
            assert!(client
                .download_resource(&file, &sentinel_path, None, &limits)
                .await
                .is_err());
            #[cfg(unix)]
            {
                let link = output_root.join("existing-link");
                std::os::unix::fs::symlink(&sentinel_path, &link)?;
                assert!(client
                    .download_resource(&file, &link, None, &limits)
                    .await
                    .is_err());
                assert!(std::fs::symlink_metadata(link)?.file_type().is_symlink());
            }
            assert_eq!(std::fs::read(sentinel_path)?, sentinel);

            let original = b"the preflight file stays intact";
            std::fs::write(profile.join("switch"), original)?;
            let switched = volume.clone().child("switch")?;
            assert!(!client.resource_info(&switched).await?.is_dir);
            let retained = profile.join("original-kept");
            std::fs::rename(profile.join("switch"), &retained)?;
            std::fs::create_dir(profile.join("switch"))?;
            std::fs::write(profile.join("switch").join("leaf.txt"), b"directory data")?;

            let mut violations = Vec::new();
            for (case, path) in [
                ("nonempty", batch),
                ("empty", volume.child("empty-dir")?),
                ("replaced-file", switched),
            ] {
                let destination = output_root.join(format!("unexpected-{case}"));
                let result = client
                    .download_resource(&path, &destination, None, &limits)
                    .await;
                let output_created = match std::fs::symlink_metadata(&destination) {
                    Ok(_) => true,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                    Err(error) => return Err(error.into()),
                };
                println!(
                    "full download directory evidence: case={case} success={} output_created={output_created}",
                    result.is_ok(),
                );
                if result.is_ok() || output_created {
                    violations.push(case);
                }
            }
            assert_eq!(std::fs::read(retained)?, original);
            assert_eq!(
                std::fs::read(profile.join("switch").join("leaf.txt"))?,
                b"directory data"
            );
            if !violations.is_empty() {
                return Err(
                    format!("complete file download must refuse directories before creating an output: {violations:?}")
                        .into(),
                );
            }
            println!(
                "file-only transfer evidence: zip_and_text=true empty_file=true large_bytes={},{} management_limit={MANAGEMENT_LIMIT} exact_range=true explicit_archives=true existing_output_preserved=true",
                large.len(),
                larger.len(),
            );
            Ok(())
        })
        .await?
    }
    .await;
    let exit = core.shutdown(Duration::from_secs(15)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    temp.close()?;
    println!("file-only transfer owned cleanup: normal_exit=true state_removed=true");
    observation
}
