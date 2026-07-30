use std::io::Write;
use std::str::FromStr;

const CPOC_BASE_URL: &'static str = "https://cpoc.jrc.ec.europa.eu/L0/";

fn main() {
    let cpop_base_url = reqwest::Url::parse(CPOC_BASE_URL).unwrap();
    let client = reqwest::blocking::Client::builder()
        .user_agent(concat!("C-ITS Rust", env!("CARGO_PKG_VERSION")))
        .https_only(true)
        .build()
        .unwrap();

    let r = client.get(cpop_base_url.join("gettlmcertificate/").unwrap()).send()
        .expect("Could not download TLM certificate")
        .error_for_status()
        .expect("Could not download TLM certificate");

    if r.headers()
        .get(reqwest::header::CONTENT_TYPE)
        .expect("No Content-Type header in response")
        != "application/octet-stream" {
        panic!("Content-Type is not application/octet-stream");
    }

    let data = r.bytes().expect("Could not download TLM certificate");
    let tlm = c_its::security::certs::Certificate::parse(&data)
        .expect("Could not parse TLM certificate");

    let tlm_report = tlm.report()
        .expect("Could not generate TLM certificate report");

    let c_its::security::certs::CertificateSubject::Hostname { hostname } = tlm_report.subject() else {
        panic!("TLM certificate does not have a hostname subject");
    };
    println!("Downloaded TLM certificate {} ({})", hostname, hex::encode_upper(tlm_report.id8()));

    let now = chrono::Utc::now();
    if &now < tlm_report.valid_from() || &now > tlm_report.valid_until() {
        panic!("TLM certificate outside of validity window");
    }

    let Some(ctl_permissions) = tlm_report.get_ctl_permission() else {
        panic!("TLM certificate does not have Certificate Trust List permissions");
    };

    if !ctl_permissions.tlm {
        panic!("TLM certificate does not have CTL TLM sign permission set");
    }

    let c_its::security::certs::CertificateSignature::SelfSigned { verifies } = tlm_report.signature() else {
        panic!("TLM certificate does not have a self-signed signature");
    };
    if !verifies {
        panic!("TLM certificate signature does not validate");
    }

    let ctl_data_dir = std::path::PathBuf::from_str("./ctl").unwrap();
    std::fs::create_dir_all(&ctl_data_dir)
        .expect("Could not create CTL data directory");
    let mut f = std::fs::File::create(ctl_data_dir.join("tlm-cert.oer"))
        .expect("Could not create TLM certificate file");
    f.write_all(&data)
        .expect("Could not write to TLM certificate file");
}