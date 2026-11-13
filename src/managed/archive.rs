//! No archive paths are materialized: only one exact regular member is copied.

use super::download::{io, rejected};
use crate::{ArchiveFormat, OfficialProgram, ProgramArchitecture as Arch, ProgramOs, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

const MAX_MEMBERS: usize = 8192;
const MAX_PROGRAM: u64 = 256 * 1024 * 1024;
const MAX_EXPANDED: u64 = 1024 * 1024 * 1024;

pub(super) fn extract(
    path: &Path,
    asset: &OfficialProgram,
    output: &mut File,
    mut check: impl FnMut() -> Result<()>,
) -> Result<[u8; 32]> {
    let suffix = match asset.archive_format() {
        ArchiveFormat::Zip => ".zip",
        ArchiveFormat::TarGz => ".tar.gz",
    };
    let root = asset
        .archive_filename()
        .strip_suffix(suffix)
        .ok_or_else(|| rejected("fixed archive name has an invalid suffix"))?;
    let expected = format!("{root}/{}", asset.executable_name());
    let file = File::open(path).map_err(|e| io("open verified archive", e))?;
    let digest = extract_archive(file, asset.archive_format(), &expected, output, &mut check)?;
    output
        .seek(SeekFrom::Start(0))
        .map_err(|e| io("inspect extracted executable", e))?;
    let mut header = Vec::with_capacity(4096);
    output
        .take(4096)
        .read_to_end(&mut header)
        .map_err(|e| io("read extracted executable header", e))?;
    check_header(&header, asset)?;
    Ok(digest)
}

fn extract_archive(
    input: File,
    format: ArchiveFormat,
    expected: &str,
    output: &mut File,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<[u8; 32]> {
    let mut seen = HashSet::new();
    let mut digest = None;
    match format {
        ArchiveFormat::Zip => {
            let mut buffer = vec![0; rawzip::RECOMMENDED_BUFFER_SIZE];
            let zip = rawzip::ZipArchive::from_file(input, &mut buffer)
                .map_err(|_| rejected("invalid ZIP archive"))?;
            let expected_count = zip.entries_hint();
            if expected_count > MAX_MEMBERS as u64 {
                return Err(rejected("archive contains too many members"));
            }
            let mut expanded = 0_u64;
            let mut count = 0_u64;
            let mut ranges = Vec::new();
            let mut entries = zip.entries(&mut buffer);
            while let Some(member) = entries
                .next_entry()
                .map_err(|_| rejected("invalid ZIP member"))?
            {
                check()?;
                count += 1;
                if count > expected_count {
                    return Err(rejected("ZIP member count exceeds its directory"));
                }
                let name = checked_name(member.file_path().as_bytes(), &mut seen)?;
                let size = member.uncompressed_size_hint();
                expanded = expanded
                    .checked_add(size)
                    .ok_or_else(|| rejected("expanded archive length overflow"))?;
                if expanded > MAX_EXPANDED {
                    return Err(rejected("expanded archive exceeds its bound"));
                }
                let kind = member.mode().value() & 0o170000;
                if member.flags().is_encrypted()
                    || member.mode().is_symlink()
                    || !matches!(kind, 0 | 0o040000 | 0o100000)
                {
                    return Err(rejected("archive contains a link or special member"));
                }
                let local = zip
                    .get_entry(member.wayfinder())
                    .map_err(|_| rejected("invalid ZIP local header"))?;
                let range = local.compressed_data_range();
                if range.1 > zip.directory_offset()
                    || ranges
                        .iter()
                        .any(|&(start, end)| range.0 < end && start < range.1)
                {
                    return Err(rejected(
                        "ZIP compressed ranges overlap or exceed the data section",
                    ));
                }
                ranges.push(range);
                if name == expected {
                    if member.is_dir() || !matches!(kind, 0 | 0o100000) {
                        return Err(rejected("selected executable is not a regular file"));
                    }
                    digest =
                        Some(match member.compression_method() {
                            rawzip::CompressionMethod::STORE => copy_program(
                                &mut local.verifying_reader(local.reader()),
                                size,
                                output,
                                check,
                            )?,
                            rawzip::CompressionMethod::DEFLATE => copy_program(
                                &mut local.verifying_reader(flate2::read::DeflateDecoder::new(
                                    local.reader(),
                                )),
                                size,
                                output,
                                check,
                            )?,
                            _ => return Err(rejected(
                                "selected ZIP executable uses an unsupported compression method",
                            )),
                        });
                }
            }
            if count != expected_count {
                return Err(rejected("ZIP member count does not match its directory"));
            }
        }
        ArchiveFormat::TarGz => {
            let gzip = flate2::read::MultiGzDecoder::new(input);
            let mut bounded = Bounded {
                input: gzip,
                remaining: MAX_EXPANDED,
                check: &mut *check,
            };
            let mut archive = tar::Archive::new(&mut bounded);
            let entries = archive
                .entries()
                .map_err(|_| rejected("invalid tar archive"))?
                .raw(true);
            for (index, entry) in entries.enumerate() {
                if index >= MAX_MEMBERS {
                    return Err(rejected("archive contains too many members"));
                }
                let mut member =
                    entry.map_err(|_| rejected("invalid or interrupted tar member"))?;
                let name = checked_name(&member.path_bytes(), &mut seen)?;
                let kind = member.header().entry_type();
                if !(kind.is_file() || kind.is_dir()) {
                    return Err(rejected("archive contains a link or special member"));
                }
                if name == expected {
                    if !kind.is_file() {
                        return Err(rejected("selected executable is not a regular file"));
                    }
                    let size = member.size();
                    // The bounded reader checks cancellation before every decompression read.
                    digest = Some(copy_program(&mut member, size, output, &mut || Ok(()))?);
                }
            }
            // Consume the gzip trailer and reject corrupt or oversized trailing streams.
            std::io::copy(&mut bounded, &mut std::io::sink())
                .map_err(|_| rejected("invalid, oversized or interrupted gzip stream"))?;
        }
    }
    check()?;
    digest.ok_or_else(|| rejected("archive has no exact regular executable member"))
}

fn checked_name(raw: &[u8], seen: &mut HashSet<String>) -> Result<String> {
    let name = std::str::from_utf8(raw).map_err(|_| rejected("archive path is not UTF-8"))?;
    let name = name.strip_suffix('/').unwrap_or(name);
    if name.is_empty()
        || name.len() > 4096
        || name.starts_with('/')
        || name.contains(['\\', '\0', ':'])
        || name.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(rejected("archive contains an unsafe path"));
    }
    if !seen.insert(name.to_owned()) {
        return Err(rejected("archive contains duplicate paths"));
    }
    Ok(name.to_owned())
}
fn copy_program(
    input: &mut impl Read,
    expected: u64,
    output: &mut File,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<[u8; 32]> {
    if expected == 0 || expected > MAX_PROGRAM {
        return Err(rejected("executable size is outside its bound"));
    }
    let mut hash = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        check()?;
        let n = input
            .read(&mut buffer)
            .map_err(|_| rejected("executable member is corrupt or interrupted"))?;
        if n == 0 {
            break;
        }
        copied += n as u64;
        if copied > expected {
            return Err(rejected("executable member exceeds its declared size"));
        }
        output
            .write_all(&buffer[..n])
            .map_err(|e| io("write partial executable", e))?;
        hash.update(&buffer[..n]);
    }
    if copied != expected {
        return Err(rejected("executable member ended early"));
    }
    Ok(hash.finalize().into())
}
struct Bounded<R, F> {
    input: R,
    remaining: u64,
    check: F,
}
impl<R: Read, F: FnMut() -> Result<()>> Read for Bounded<R, F> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        (self.check)().map_err(|_| std::io::Error::other("archive operation ended"))?;
        let limit = output
            .len()
            .min(64 * 1024)
            .min(self.remaining.saturating_add(1) as usize);
        let n = self.input.read(&mut output[..limit])?;
        if n as u64 > self.remaining {
            return Err(std::io::Error::other("expanded archive bound exceeded"));
        }
        self.remaining -= n as u64;
        Ok(n)
    }
}

fn check_header(bytes: &[u8], asset: &OfficialProgram) -> Result<()> {
    let target = asset.target();
    let arch = target.architecture();
    let valid = match target.os() {
        ProgramOs::MacOs => {
            let cpu = match arch {
                Arch::Amd64 => 0x0100_0007_u32,
                Arch::Arm64 => 0x0100_000c,
                _ => 0,
            };
            bytes.len() >= 32
                && bytes[..4] == [0xcf, 0xfa, 0xed, 0xfe]
                && bytes[4..8] == cpu.to_le_bytes()
                && bytes[12..16] == 2_u32.to_le_bytes()
        }
        ProgramOs::Windows => {
            let cpu = match arch {
                Arch::X86 => 0x014c_u16,
                Arch::Amd64 => 0x8664,
                Arch::Arm64 => 0xaa64,
                _ => 0,
            };
            if bytes.len() < 64 || &bytes[..2] != b"MZ" {
                false
            } else {
                let offset =
                    u32::from_le_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]) as usize;
                bytes
                    .get(offset..offset.saturating_add(26))
                    .is_some_and(|header| {
                        let characteristics = u16::from_le_bytes([header[22], header[23]]);
                        let magic = if arch == Arch::X86 {
                            0x010b_u16
                        } else {
                            0x020b
                        };
                        header[..4] == *b"PE\0\0"
                            && header[4..6] == cpu.to_le_bytes()
                            && characteristics & 0x0002 != 0
                            && characteristics & 0x2000 == 0
                            && header[24..26] == magic.to_le_bytes()
                    })
            }
        }
        ProgramOs::Linux => {
            let (class, endian, cpu) = match arch {
                Arch::X86 => (1, 1, 3_u16),
                Arch::Amd64 => (2, 1, 62),
                Arch::Arm64 => (2, 1, 183),
                Arch::Arm | Arch::ArmHf | Arch::ArmV6 => (1, 1, 40),
                Arch::Mips => (1, 2, 8),
                Arch::MipsLe => (1, 1, 8),
                Arch::Mips64 => (2, 2, 8),
                Arch::Mips64Le => (2, 1, 8),
                Arch::Ppc64Le => (2, 1, 21),
                Arch::RiscV64 => (2, 1, 243),
                Arch::S390x => (2, 2, 22),
                Arch::Loong64 => (2, 1, 258),
            };
            let encoded = if endian == 1 {
                cpu.to_le_bytes()
            } else {
                cpu.to_be_bytes()
            };
            let object_type = if bytes.len() >= 18 {
                if endian == 1 {
                    u16::from_le_bytes([bytes[16], bytes[17]])
                } else {
                    u16::from_be_bytes([bytes[16], bytes[17]])
                }
            } else {
                0
            };
            bytes.len() >= 64
                && &bytes[..4] == b"\x7fELF"
                && bytes[4] == class
                && bytes[5] == endian
                && bytes[6] == 1
                && matches!(object_type, 2 | 3)
                && bytes[18..20] == encoded
        }
    };
    if !valid {
        return Err(rejected(
            "executable header does not match the selected program OS and CPU",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn zip_member(writer: &mut rawzip::ZipArchiveWriter<File>, name: &str, data: &[u8], mode: u32) {
        let (mut entry, config) = writer
            .new_file(name)
            .unix_permissions(mode)
            .start()
            .unwrap();
        let mut content = config.wrap(&mut entry);
        content.write_all(data).unwrap();
        let (_, descriptor) = content.finish().unwrap();
        entry.finish(descriptor).unwrap();
    }

    #[test]
    fn archive_paths_reject_traversal_aliases_links_and_duplicate_members() {
        for name in [
            "../outside",
            "/absolute",
            "C:/outside",
            "root\\outside",
            "root/./program",
            "root//program",
            "root/../program",
            "root/stream:ads",
            "root/zero\0",
        ] {
            assert!(checked_name(name.as_bytes(), &mut HashSet::new()).is_err());
        }
        let mut seen = HashSet::new();
        checked_name(b"root/program", &mut seen).unwrap();
        assert!(checked_name(b"root/program", &mut seen).is_err());
    }

    #[test]
    fn zip_selects_exact_regular_core_and_rejects_symbolic_link() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("sample.zip");
        let mut writer = rawzip::ZipArchiveWriter::new(File::create(&path).unwrap());
        zip_member(
            &mut writer,
            "root/services/program",
            b"wrong basename match",
            0o100600,
        );
        zip_member(&mut writer, "root/program", b"synthetic core", 0o100600);
        writer.finish().unwrap();
        let mut output = tempfile::tempfile().unwrap();
        let digest = extract_archive(
            File::open(&path).unwrap(),
            ArchiveFormat::Zip,
            "root/program",
            &mut output,
            &mut || Ok(()),
        )
        .unwrap();
        assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(b"synthetic core")));
        let mut writer = rawzip::ZipArchiveWriter::new(File::create(&path).unwrap());
        zip_member(&mut writer, "root/program", b"../outside", 0o120777);
        writer.finish().unwrap();
        assert!(extract_archive(
            File::open(path).unwrap(),
            ArchiveFormat::Zip,
            "root/program",
            &mut output,
            &mut || Ok(())
        )
        .is_err());
        assert!(!root.path().join("outside").exists());
    }

    #[test]
    fn actual_zip_traversal_duplicates_corruption_and_missing_core_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("adversarial.zip");
        for (index, names) in [
            vec!["aa/outside", "root/program"],
            vec!["root/program", "root/prograx"],
            vec!["services/program"],
        ]
        .into_iter()
        .enumerate()
        {
            let mut writer = rawzip::ZipArchiveWriter::new(File::create(&path).unwrap());
            for name in names {
                zip_member(&mut writer, name, b"synthetic", 0o100600);
            }
            writer.finish().unwrap();
            // The writer normalizes paths and may deduplicate names. Mutate both
            // raw headers to exercise actual adversarial archives instead.
            let mut bytes = std::fs::read(&path).unwrap();
            let replacement = match index {
                0 => Some((&b"aa/outside"[..], &b"../outside"[..])),
                1 => Some((&b"root/prograx"[..], &b"root/program"[..])),
                _ => None,
            };
            if let Some((from, to)) = replacement {
                for position in (0..=bytes.len() - from.len())
                    .filter(|&p| bytes[p..p + from.len()] == *from)
                    .collect::<Vec<_>>()
                {
                    bytes[position..position + from.len()].copy_from_slice(to);
                }
                std::fs::write(&path, bytes).unwrap();
            }
            assert!(
                extract_archive(
                    File::open(&path).unwrap(),
                    ArchiveFormat::Zip,
                    "root/program",
                    &mut tempfile::tempfile().unwrap(),
                    &mut || Ok(())
                )
                .is_err(),
                "adversarial ZIP case {index}"
            );
        }
        let mut writer = rawzip::ZipArchiveWriter::new(File::create(&path).unwrap());
        zip_member(
            &mut writer,
            "root/program",
            b"synthetic corruption marker",
            0o100600,
        );
        writer.finish().unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let position = bytes
            .windows(27)
            .position(|w| w == b"synthetic corruption marker")
            .unwrap();
        bytes[position] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(extract_archive(
            File::open(path).unwrap(),
            ArchiveFormat::Zip,
            "root/program",
            &mut tempfile::tempfile().unwrap(),
            &mut || Ok(())
        )
        .is_err());
        assert!(!root.path().join("outside").exists());
    }

    #[test]
    fn tar_gzip_regular_core_is_exact_and_links_special_files_and_corruption_fail() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("sample.tar.gz");
        for kind in [
            tar::EntryType::Regular,
            tar::EntryType::Symlink,
            tar::EntryType::Link,
            tar::EntryType::Fifo,
        ] {
            let gzip = flate2::write::GzEncoder::new(
                File::create(&path).unwrap(),
                flate2::Compression::default(),
            );
            let mut builder = tar::Builder::new(gzip);
            let mut header = tar::Header::new_ustar();
            header.set_path("root/program").unwrap();
            header.set_entry_type(kind);
            header.set_mode(0o755);
            if kind.is_file() {
                header.set_size(14);
            } else {
                header.set_size(0);
                header.set_link_name("../outside").unwrap();
            }
            header.set_cksum();
            let data = if kind.is_file() {
                &b"synthetic core"[..]
            } else {
                &b""[..]
            };
            builder.append(&header, data).unwrap();
            builder.into_inner().unwrap().finish().unwrap();
            let result = extract_archive(
                File::open(&path).unwrap(),
                ArchiveFormat::TarGz,
                "root/program",
                &mut tempfile::tempfile().unwrap(),
                &mut || Ok(()),
            );
            if kind.is_file() {
                assert_eq!(
                    result.unwrap(),
                    <[u8; 32]>::from(Sha256::digest(b"synthetic core"))
                );
            } else {
                assert!(result.is_err());
            }
        }
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.truncate(bytes.len() - 5);
        std::fs::write(&path, bytes).unwrap();
        assert!(extract_archive(
            File::open(path).unwrap(),
            ArchiveFormat::TarGz,
            "root/program",
            &mut tempfile::tempfile().unwrap(),
            &mut || Ok(())
        )
        .is_err());
        assert!(!root.path().join("outside").exists());
    }
}
