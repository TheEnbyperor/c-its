mod leap_seconds {
    include!(concat!(env!("OUT_DIR"), "/leap_seconds.rs"));
}

fn get_leap_seconds(ntp_time: i64) -> i64 {
    for (c, v) in leap_seconds::LEAP_SECONDS.iter().rev() {
        if ntp_time >= *c {
            return *v
        }
    }
    0
}

pub fn tai_from_chrono<const N: i64, Tz: chrono::TimeZone>(ts: &chrono::DateTime<Tz>) -> tai_time::TaiTime<N> {
    let ntp_time = ts.timestamp() + 2208988800;
    let leap_seconds = get_leap_seconds(ntp_time);
    tai_time::TaiTime::from_chrono_date_time(ts, leap_seconds)
}

pub fn chrono_from_tai<const N: i64>(ts: &tai_time::TaiTime<N>) -> chrono::DateTime<chrono::Utc> {
    let ntp_time = ts.to_tai_time::<-2208988800>().unwrap().as_secs();
    let leap_seconds = get_leap_seconds(ntp_time);
    ts.to_chrono_date_time(leap_seconds).unwrap()
}

#[test]
fn test_leap_seconds() {
    let time = chrono::DateTime::parse_from_rfc3339("2026-07-02T13:12:00Z").unwrap().with_timezone(&chrono::Utc);
    let tai_time: crate::geo_networking::GnTaiTime = tai_from_chrono(&time);
    let recalculated_time = chrono_from_tai(&tai_time);
    assert_eq!(time, recalculated_time);
    let time = chrono::DateTime::parse_from_rfc3339("2004-07-02T13:12:00Z").unwrap().with_timezone(&chrono::Utc);
    let tai_time: crate::geo_networking::GnTaiTime = tai_from_chrono(&time);
    let recalculated_time = chrono_from_tai(&tai_time);
    assert_eq!(time, recalculated_time);
}

pub fn decode_ita2(bits: &rasn::types::FixedBitString<10>) -> Result<alloc::string::String, u8> {
    bits[..10]
        .chunks_exact(5)
        .map(|chunk| {
            let code = chunk
                .iter()
                .fold(0u8, |value, bit| (value << 1) | u8::from(*bit));

            ita2_letter(code).ok_or(code)
        })
        .collect()
}

fn ita2_letter(code: u8) -> Option<char> {
    Some(match code {
        3 => 'A', 25 => 'B', 14 => 'C',  9 => 'D',
        1 => 'E', 13 => 'F', 26 => 'G', 20 => 'H',
        6 => 'I', 11 => 'J', 15 => 'K', 18 => 'L',
        28 => 'M', 12 => 'N', 24 => 'O', 22 => 'P',
        23 => 'Q', 10 => 'R',  5 => 'S', 16 => 'T',
        7 => 'U', 30 => 'V', 19 => 'W', 29 => 'X',
        21 => 'Y', 17 => 'Z',
        _ => return None, // NUL, FIGS, LTRS, controls, etc.
    })
}

pub fn serialize_mac_address<S: serde::Serializer>(
    mac: &ieee80211::mac_parser::MACAddress,
    ser: S,
) -> Result<S::Ok, S::Error> {
    let str = mac
        .iter()
        .map(|s| alloc::format!("{:02X}", s))
        .collect::<alloc::vec::Vec<_>>()
        .join(":");
    ser.serialize_str(str.as_str())
}

pub fn serialize_bytes<S: serde::Serializer>(
    data: &[u8],
    ser: S,
) -> Result<S::Ok, S::Error> {
    use base64::Engine;
    let str = base64::prelude::BASE64_STANDARD.encode(&data);
    ser.serialize_str(str.as_str())
}

pub fn serialize_bytes_hex<S: serde::Serializer>(
    data: &[u8],
    ser: S,
) -> Result<S::Ok, S::Error> {
    let str = data
        .iter()
        .map(|s| alloc::format!("{:02X}", s))
        .collect::<alloc::vec::Vec<_>>()
        .join("");
    ser.serialize_str(str.as_str())
}