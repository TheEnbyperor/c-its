use std::io::Write;
use std::str::FromStr;

const CPOC_BASE_URL: &'static str = "https://cpoc.jrc.ec.europa.eu/L0/";

#[derive(Debug)]
struct RootCAEntry {
    root_ca_bytes: Vec<u8>,
    root_ca: c_its::security::certs::CertificateReport,
    distribution_centre: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct CertMeta {
    distribution_centre: String,
}

fn main() {
    pretty_env_logger::init();

    let now = chrono::Utc::now();
    let cpop_base_url = reqwest::Url::parse(CPOC_BASE_URL).unwrap();
    let ctl_data_dir = std::path::PathBuf::from_str("./ctl").unwrap();
    let client = reqwest::blocking::Client::builder()
        .user_agent(concat!("C-ITS Rust", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap();

    let tlm_cert = std::fs::read(ctl_data_dir.join("tlm-cert.oer"))
        .expect("Unable to open TLM certificate");
    let tlm_cert = c_its::security::certs::Certificate::parse(&tlm_cert)
        .expect("Could not parse TLM certificate");
    let tlm_report = tlm_cert.report()
        .expect("Could not generate TLM certificate report");

    let c_its::security::certs::CertificateSubject::Hostname { hostname } = tlm_report.subject() else {
        panic!("TLM certificate does not have a hostname subject");
    };
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

    let mut security_store = c_its::security::SecurityStore::new();
    security_store.insert_cert(tlm_cert);

    let id8_hex = hex::encode_upper(tlm_report.id8());
    println!("Requesting CTL for TLM certificate {} ({})", hostname, id8_hex);

    let r = client.get(cpop_base_url.join(&format!("getectl/{}", id8_hex)).unwrap())
        .send()
        .expect("Could not download CTL")
        .error_for_status()
        .expect("Could not download CTL");

    if r.headers()
        .get(reqwest::header::CONTENT_TYPE)
        .expect("No Content-Type header in response")
        != "application/octet-stream" {
        panic!("Content-Type is not application/octet-stream");
    }
    let data = r.bytes().expect("Could not download CTL");
    let ctl: rasn_its::ts103097::EtsiTs103097DataSigned<c_its::asn::etsi_ts_102941_messages_ca::TlmCertificateTrustListMessage> = rasn::oer::decode(&data)
        .expect("Could not decode CTL");
    if ctl.protocol_version != 3 {
        panic!("Unsupported protocol version for CTL {}", ctl.protocol_version);
    }
    let rasn_its::ieee1609dot2::Ieee1609Dot2Content::SignedData(ref ctl) = ctl.content else {
        unreachable!();
    };
    let Some(ref ctl_inner_data) = ctl.tbs_data.payload.data else {
        panic!("CTL does not contain any data")
    };

    let ctl_report = security_store.security_report(ctl)
        .expect("Unable to generate security report for CTL");

    if *ctl_report.provider_service() != c_its::security::certs::ProviderService::CTL {
        panic!("CTL message is not declared as a CTl service message");
    }
    if !ctl_report.signature_verifies() {
        panic!("Signature over CTL does not verify");
    }
    let ctl_report_certs = ctl_report.certificates();
    if ctl_report_certs.len() != 1 || ctl_report_certs[0] != tlm_report {
        panic!("CTL invalidly signed");
    }

    if ctl_inner_data.protocol_version != 3 {
        panic!("Unsupported protocol version for CTL inner data {}", ctl_inner_data.protocol_version);
    }
    let rasn_its::ieee1609dot2::Ieee1609Dot2Content::UnsecuredData(ref ctl_inner_data) = ctl_inner_data.content else {
        panic!("CTL does not contain any data")
    };

    let ctl_inner: c_its::asn::etsi_ts_102941_messages_ca::EtsiTs102941Data = rasn::oer::decode(&ctl_inner_data.0)
        .expect("Could not decode CTL");

    let c_its::asn::etsi_ts_102941_messages_ca::EtsiTs102941DataContent::certificateTrustListTlm(ref ctl_tlm) = ctl_inner.content else {
        panic!("CTL data does not a CTL element");
    };
    if !ctl_tlm.0.is_full_ctl {
        panic!("CTL is not a full CTL");
    }
    let next_update = c_its::security::certs::time32_to_utc(&ctl_tlm.0.next_update);
    if next_update < now {
        panic!("CTL has expired");
    }

    let mut root_cas = std::collections::HashMap::new();

    for command in &ctl_tlm.0.ctl_commands {
        match command {
            c_its::asn::etsi_ts102941_trust_lists::CtlCommand::add(ctl_entry) => match ctl_entry {
                c_its::asn::etsi_ts102941_trust_lists::CtlEntry::rca(root_cert) => {
                    if !ctl_permissions.root_ca {
                        panic!("TLM certificate does not have CTL Root CA sign permission set");
                    }

                    let root_cert = c_its::security::certs::Certificate::new(&root_cert.selfsigned_root_ca);
                    let root_cert_report = root_cert.report()
                        .expect("Could not generate report for root CA");

                    if root_cas.insert(root_cert_report.id8(), RootCAEntry {
                        root_ca_bytes: root_cert.to_bytes(),
                        root_ca: root_cert_report,
                        distribution_centre: None,
                    }).is_some() {
                        panic!("CTL contains multiple roots with the same ID8")
                    };
                }
                c_its::asn::etsi_ts102941_trust_lists::CtlEntry::dc(dc) => {
                    let dc_url = dc.url.0.to_string();
                    for rca_id in dc.cert.iter().map(|id| *id.0) {
                        let std::collections::hash_map::Entry::Occupied(mut entry) = root_cas.entry(rca_id) else {
                             continue;
                         };
                        entry.get_mut().distribution_centre = Some(dc_url.clone());
                    }
                }
                c_its::asn::etsi_ts102941_trust_lists::CtlEntry::tlm(_) => {}
                o => println!("Unknown CTL entry: {:?}", o)
            }
            c_its::asn::etsi_ts102941_trust_lists::CtlCommand::delete(_) => panic!("Delete command in full CTL"),
            _ => {}
        }
    }

    for (_, root_ca) in root_cas {
        let id8_hex = hex::encode_upper(root_ca.root_ca.id8());
        let Some(distribution_centre) = root_ca.distribution_centre else {
            log::warn!("No distribution centre for root {}", id8_hex);
            continue;
        };

        let cert_file = ctl_data_dir.join(format!("root-{}-{}.oer", id8_hex, root_ca.root_ca.subject()));
        let cert_meta_file = ctl_data_dir.join(format!("root-{}-{}.json", id8_hex, root_ca.root_ca.subject()));

        let cert_meta_data = serde_json::to_vec(&CertMeta {
            distribution_centre,
        }).unwrap();

        if let Err(err) = std::fs::write(cert_file, &root_ca.root_ca_bytes) {
            panic!("Could not write cert file: {}", err);
        }
        if let Err(err) = std::fs::write(cert_meta_file, &cert_meta_data) {
            panic!("Could not write cert meta file: {}", err);
        }
    }
}