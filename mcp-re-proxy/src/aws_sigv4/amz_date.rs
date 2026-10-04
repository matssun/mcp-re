//! The SigV4 signing instant: one clock reading rendered once as both the
//! `YYYYMMDDTHHMMSSZ` request timestamp and its `YYYYMMDD` credential-scope date.

/// A SigV4 instant. Both renderings are produced together from one UNIX timestamp, so
/// the credential-scope date can never disagree with the request timestamp.
///
/// `pub` because [`super::SigV4Signer::sign`] is `pub` and takes it.
#[derive(Debug)]
pub struct AmzDate {
    date: String,
    instant: String,
}

impl AmzDate {
    /// Render a UNIX timestamp (UTC). Hand-rolled via the civil-from-days algorithm to
    /// avoid a date-library dependency.
    pub fn from_unix(unix_secs: u64) -> Self {
        let days = (unix_secs / 86_400) as i64;
        let sod = unix_secs % 86_400;
        let (hour, min, sec) = (sod / 3600, (sod % 3600) / 60, sod % 60);
        let (y, m, d) = civil_from_days(days);
        let date = format!("{y:04}{m:02}{d:02}");
        let instant = format!("{date}T{hour:02}{min:02}{sec:02}Z");
        AmzDate { date, instant }
    }

    /// The `YYYYMMDDTHHMMSSZ` request timestamp.
    pub fn as_str(&self) -> &str {
        &self.instant
    }

    /// The `YYYYMMDD` credential-scope date.
    pub fn datestamp(&self) -> &str {
        &self.date
    }
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 → (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GOLDEN: UTC formatting matches well-known timestamps.
    #[test]
    fn amz_date_formats_known_epochs() {
        assert_eq!(AmzDate::from_unix(0).as_str(), "19700101T000000Z");
        assert_eq!(AmzDate::from_unix(0).datestamp(), "19700101");
        // 2001-09-09T01:46:40Z — the well-known 1e9 UNIX timestamp.
        assert_eq!(
            AmzDate::from_unix(1_000_000_000).as_str(),
            "20010909T014640Z"
        );
        assert_eq!(AmzDate::from_unix(1_000_000_000).datestamp(), "20010909");
        // 2015-08-30T12:36:00Z — the get-vanilla vector's instant.
        assert_eq!(
            AmzDate::from_unix(1_440_938_160).as_str(),
            "20150830T123600Z"
        );
        assert_eq!(AmzDate::from_unix(1_440_938_160).datestamp(), "20150830");
    }
}
