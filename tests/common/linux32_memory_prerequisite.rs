//! Test-only reproduction of the fixed upstream memory parser's integer width.

pub(super) fn unusable_wrapped_total(meminfo: &str) -> Result<bool, &'static str> {
    let mut total = None;
    for line in meminfo.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("MemTotal:") {
            continue;
        }
        if total.is_some() {
            return Err("multiple MemTotal records are not a verified prerequisite");
        }
        let kib: i32 = fields
            .next()
            .ok_or("MemTotal value missing")?
            .parse()
            .map_err(|_| "MemTotal is outside the verified Go int32 input")?;
        if kib <= 0 || fields.next() != Some("kB") || fields.next().is_some() {
            return Err("MemTotal units or fields are outside the verified input");
        }
        total = Some(kib);
    }
    let kib = total.ok_or("MemTotal record missing")?;
    // ghw v0.13.0 multiplies Go int before converting to int64. On a 32-bit
    // target, a nonpositive result makes its native load return an error.
    Ok(kib.wrapping_mul(1024) <= 0)
}

#[cfg(test)]
mod contracts {
    use super::*;

    #[test]
    fn only_nonpositive_int32_results_match_the_fixed_native_refusal() {
        for kib in [2_097_152, 3_145_728, 4_194_304, 7_340_032, 8_388_608] {
            assert!(unusable_wrapped_total(&format!("MemTotal: {kib} kB\n")).unwrap());
        }
        for kib in [1, 1_048_576, 5_242_880] {
            assert!(!unusable_wrapped_total(&format!("MemTotal: {kib} kB\n")).unwrap());
        }
    }

    #[test]
    fn unknown_units_duplicate_missing_and_out_of_range_inputs_stay_unverified() {
        for value in [
            "MemFree: 1 kB\n",
            "MemTotal: 3145728 bytes\n",
            "MemTotal: 3145728 kB extra\n",
            "MemTotal: -1 kB\n",
            "MemTotal: 0 kB\n",
            "MemTotal: 2147483648 kB\n",
            "MemTotal: 3145728 kB\nMemTotal: 3145728 kB\n",
        ] {
            assert!(unusable_wrapped_total(value).is_err());
        }
    }
}
