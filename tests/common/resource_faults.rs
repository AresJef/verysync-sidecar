//! Bounded synthetic files and independent retained-prefix verification.
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::Path,
};
type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub fn write_pattern(path: &Path, bytes: u64) -> TestResult<(Vec<u8>, [u8; 32])> {
    let pattern: Vec<u8> = (0..65536).map(|n| (n % 251) as u8).collect();
    let mut file = std::fs::File::create(path)?;
    let mut hash = Sha256::new();
    let mut left = bytes;
    while left != 0 {
        let size = left.min(pattern.len() as u64) as usize;
        file.write_all(&pattern[..size])?;
        hash.update(&pattern[..size]);
        left -= size as u64;
    }
    file.sync_all()?;
    Ok((pattern, hash.finalize().into()))
}

pub fn verify_pattern(path: &Path, pattern: &[u8], limit: u64) -> TestResult<(u64, [u8; 32])> {
    let mut file = std::fs::File::open(path)?;
    let mut buffer = vec![0; 65536];
    let mut total = 0_u64;
    let mut hash = Sha256::new();
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        assert!(
            total + count as u64 <= limit,
            "retained file exceeds the synthetic source bound"
        );
        assert!(
            buffer[..count]
                .iter()
                .enumerate()
                .all(|(n, b)| *b == pattern[(total as usize + n) % pattern.len()]),
            "retained file must match the exact source prefix"
        );
        hash.update(&buffer[..count]);
        total += count as u64;
    }
    Ok((total, hash.finalize().into()))
}
