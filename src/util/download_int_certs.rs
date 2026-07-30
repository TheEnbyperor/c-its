use std::io::Write;
use std::str::FromStr;

#[derive(Debug, serde::Deserialize)]
struct CertMeta {
    distribution_centre: String,
}

#[derive(Debug, serde::Serialize)]
struct IntCertMeta {
    aa_access_point: String,
}

#[derive(Debug)]
struct EACertEntry {
    ea_cert_bytes: Vec<u8>,
    ea_cert: c_its::security::certs::CertificateReport,
    aa_access_point: String,
}

#[derive(Debug)]
struct AACertEntry {
    aa_cert_bytes: Vec<u8>,
    aa_cert: c_its::security::certs::CertificateReport,
    access_point: String,
}

fn join_preserving_base(
    base: &reqwest::Url,
    relative: &str,
) -> Result<reqwest::Url, url::ParseError> {
    let mut base = base.clone();

    if !base.path().ends_with('/') {
        base.path_segments_mut()
            .unwrap()
            .push("");
    }

    base.join(relative)
}

struct State<'a> {
    now: chrono::DateTime<chrono::Utc>,
    client: &'a reqwest::blocking::Client,
    security_store: c_its::security::SecurityStore,
    ctl_data_dir: &'a std::path::Path,
    root_ca_id8_hex: String,
    root_ca_meta: CertMeta,
    root_ca_path: std::path::PathBuf,
    root_ca_report: c_its::security::certs::CertificateReport,
    root_ca_dc: reqwest::Url,
}

fn sync_ctl(state: &mut State) {
    let Some(ctl_permissions) = state.root_ca_report.get_ctl_permission() else {
        log::error!("Root CA certificate does not have Certificate Trust List permissions");
        return;;
    };

    log::info!("Requesting CTL from {} for CA {}", state.root_ca_meta.distribution_centre, state.root_ca_path.display());
    let r = match state.client.get(join_preserving_base(&state.root_ca_dc, &format!("getctl/{}", &state.root_ca_id8_hex)).unwrap()).send() {
        Ok(r) => match r.error_for_status() {
            Ok(r) => r,
            Err(err) => {
                log::warn!("Unable to download CTL: {}", err);
                return;
            }
        },
        Err(err) => {
            log::warn!("Unable to download CTL: {}", err);
            return;
        }
    };
    let data = match r.bytes() {
        Ok(data) => data,
        Err(err) => {
            log::warn!("Unable to download CTL: {}", err);
            return;
        }
    };
    let ctl: rasn_its::ts103097::EtsiTs103097DataSigned<c_its::asn::etsi_ts_102941_messages_ca::RcaCertificateTrustListMessage> = match rasn::oer::decode(&data) {
        Ok(data) => data,
        Err(err) => {
            log::error!("Could not decode CTL: {}", err);
            return;
        }
    };
    if ctl.protocol_version != 3 {
        log::warn!("Unsupported protocol version for CTL {}", ctl.protocol_version);
        return;
    }
    let rasn_its::ieee1609dot2::Ieee1609Dot2Content::SignedData(ref ctl) = ctl.content else {
        unreachable!();
    };
    let Some(ref ctl_inner_data) = ctl.tbs_data.payload.data else {
        log::error!("CTL does not contain any data");
        return;
    };

    let ctl_report = match state.security_store.security_report(ctl) {
        Ok(r) => r,
        Err(err) => {
            log::error!("Unable to generate security report for CTL: {}", err);
            return;
        }
    };
    if *ctl_report.provider_service() != c_its::security::certs::ProviderService::CTL {
        log::error!("CTL message is not declared as a CTl service message");
        return;
    }
    if !ctl_report.signature_verifies() {
        log::error!("Signature over CTL does not verify");
        return;
    }
    let ctl_report_certs = ctl_report.certificates();
    if ctl_report_certs.len() != 1 || ctl_report_certs[0] != state.root_ca_report {
        log::error!("CTL invalidly signed");
        return;
    }

    if ctl_inner_data.protocol_version != 3 {
        log::warn!("Unsupported protocol version for CTL inner data {}", ctl_inner_data.protocol_version);
        return;
    }
    let rasn_its::ieee1609dot2::Ieee1609Dot2Content::UnsecuredData(ref ctl_inner_data) = ctl_inner_data.content else {
        log::error!("CTL does not contain any data");
        return;
    };

    let ctl_inner: c_its::asn::etsi_ts_102941_messages_ca::EtsiTs102941Data = match rasn::oer::decode(&ctl_inner_data.0) {
        Ok(data) => data,
        Err(err) => {
            log::error!("Could not decode CTL inner data: {}", err);
            return;
        }
    };
    let c_its::asn::etsi_ts_102941_messages_ca::EtsiTs102941DataContent::certificateTrustListRca(ref ctl_root) = ctl_inner.content else {
        log::error!("CTL data does not a CTL element");
        return;
    };
    if !ctl_root.0.is_full_ctl {
        log::error!("CTL is not a full CTL");
        return;
    }
    let next_update = c_its::security::certs::time32_to_utc(&ctl_root.0.next_update);
    if next_update < state.now {
        log::error!("CTL has expired");
        return;
    }

    let mut ea_certs = std::collections::HashMap::new();
    let mut aa_certs = std::collections::HashMap::new();

    for command in &ctl_root.0.ctl_commands {
        match command {
            c_its::asn::etsi_ts102941_trust_lists::CtlCommand::add(ctl_entry) => match ctl_entry {
                c_its::asn::etsi_ts102941_trust_lists::CtlEntry::ea(ea_cert_entry) => {
                    if !ctl_permissions.enrollment_authority {
                        log::error!("Root CA certificate does not have EA certificate sign permission set");
                        continue;
                    }

                    let ea_cert = c_its::security::certs::Certificate::new(&ea_cert_entry.ea_certificate);
                    let ea_cert_report = match ea_cert.report() {
                        Ok(report) => report,
                        Err(err) => {
                            log::error!("Could not generate report for EA cert: {}", err);
                            continue;
                        }
                    };

                    log::info!("Got EA cert {}", ea_cert_report.subject());

                    if ea_certs.insert(ea_cert_report.id8(), EACertEntry {
                        ea_cert_bytes: ea_cert.to_bytes(),
                        ea_cert: ea_cert_report,
                        aa_access_point: ea_cert_entry.aa_access_point.0.to_string(),
                    }).is_some() {
                        log::error!("Multiple EA certs with the same ID8");
                        continue;
                    };
                }
                c_its::asn::etsi_ts102941_trust_lists::CtlEntry::aa(aa_cert_entry) => {
                    if !ctl_permissions.authorization_authority {
                        log::error!("Root CA certificate does not have AA certificate sign permission set");
                        continue;
                    }

                    let aa_cert = c_its::security::certs::Certificate::new(&aa_cert_entry.aa_certificate);
                    let aa_cert_report = match aa_cert.report() {
                        Ok(report) => report,
                        Err(err) => {
                            log::error!("Could not generate report for AA cert: {}", err);
                            continue;
                        }
                    };

                    log::info!("Got AA cert {}", aa_cert_report.subject());

                    if aa_certs.insert(aa_cert_report.id8(), AACertEntry {
                        aa_cert_bytes: aa_cert.to_bytes(),
                        aa_cert: aa_cert_report,
                        access_point: aa_cert_entry.access_point.0.to_string(),
                    }).is_some() {
                        log::error!("Multiple AA certs with the same ID8");
                        continue;
                    };
                }
                c_its::asn::etsi_ts102941_trust_lists::CtlEntry::dc(_) => {},
                o => log::warn!("Unknown CTL entry: {:?}", o)
            }
            c_its::asn::etsi_ts102941_trust_lists::CtlCommand::delete(_) => {
                log::error!("Delete command in full CTL");
                continue;
            }
            _ => {}
        }
    }

    for (_, ea_cert) in ea_certs {
        let id8_hex = hex::encode_upper(ea_cert.ea_cert.id8());

        let cert_file = state.ctl_data_dir.join(format!("ea-{}-{}.oer", id8_hex, ea_cert.ea_cert.subject()));
        let cert_meta_file = state.ctl_data_dir.join(format!("ea-{}-{}.json", id8_hex, ea_cert.ea_cert.subject()));

        let cert_meta_data = serde_json::to_vec(&IntCertMeta {
            aa_access_point: ea_cert.aa_access_point,
        }).unwrap();

        if let Err(err) = std::fs::write(cert_file, &ea_cert.ea_cert_bytes) {
            panic!("Could not write cert file: {}", err);
        }
        if let Err(err) = std::fs::write(cert_meta_file, &cert_meta_data) {
            panic!("Could not write cert meta file: {}", err);
        }
    }

    for (_, aa_cert) in aa_certs {
        let id8_hex = hex::encode_upper(aa_cert.aa_cert.id8());

        let cert_file = state.ctl_data_dir.join(format!("aa-{}-{}.oer", id8_hex, aa_cert.aa_cert.subject()));
        let cert_meta_file = state.ctl_data_dir.join(format!("aa-{}-{}.json", id8_hex, aa_cert.aa_cert.subject()));

        let cert_meta_data = serde_json::to_vec(&IntCertMeta {
            aa_access_point: aa_cert.access_point,
        }).unwrap();

        if let Err(err) = std::fs::write(cert_file, &aa_cert.aa_cert_bytes) {
            panic!("Could not write cert file: {}", err);
        }
        if let Err(err) = std::fs::write(cert_meta_file, &cert_meta_data) {
            panic!("Could not write cert meta file: {}", err);
        }
    }
}

fn sync_crl(state: &mut State) {
    if !state.root_ca_report.has_crl_permission() {
        log::error!("Root CA certificate does not have Certificate Revocation List permissions");
        return;;
    };

    log::info!("Requesting CRL from {} for CA {}", state.root_ca_meta.distribution_centre, state.root_ca_path.display());
    let r = match state.client.get(join_preserving_base(&state.root_ca_dc, &format!("getcrl/{}", state.root_ca_id8_hex)).unwrap()).send() {
        Ok(r) => match r.error_for_status() {
            Ok(r) => r,
            Err(err) => {
                log::warn!("Unable to download CRL: {}", err);
                return;
            }
        },
        Err(err) => {
            log::warn!("Unable to download CRL: {}", err);
            return;
        }
    };
    let crl_data = match r.bytes() {
        Ok(data) => data,
        Err(err) => {
            log::warn!("Unable to download CRL: {}", err);
            return;
        }
    };
    let crl: rasn_its::ts103097::EtsiTs103097DataSigned<c_its::asn::etsi_ts102941_trust_lists::ToBeSignedCrl> = match rasn::oer::decode(&crl_data) {
        Ok(data) => data,
        Err(err) => {
            log::error!("Could not decode CTL: {}", err);
            return;
        }
    };
    if crl.protocol_version != 3 {
        log::warn!("Unsupported protocol version for CRL {}", crl.protocol_version);
        return;
    }
    let rasn_its::ieee1609dot2::Ieee1609Dot2Content::SignedData(ref crl) = crl.content else {
        unreachable!();
    };
    let Some(ref crl_inner_data) = crl.tbs_data.payload.data else {
        log::error!("CRL does not contain any data");
        return;
    };

    let crl_report = match state.security_store.security_report(crl) {
        Ok(r) => r,
        Err(err) => {
            log::error!("Unable to generate security report for CRL: {}", err);
            return;
        }
    };
    if *crl_report.provider_service() != c_its::security::certs::ProviderService::CRL {
        log::error!("CRL message is not declared as a CRl service message");
        return;
    }
    if !crl_report.signature_verifies() {
        log::error!("Signature over CRL does not verify");
        return;
    }
    let ctl_report_certs = crl_report.certificates();
    if ctl_report_certs.len() != 1 || ctl_report_certs[0] != state.root_ca_report {
        log::error!("CRL invalidly signed");
        return;
    }

    if crl_inner_data.protocol_version != 3 {
        log::warn!("Unsupported protocol version for CTL inner data {}", crl_inner_data.protocol_version);
        return;
    }
    let rasn_its::ieee1609dot2::Ieee1609Dot2Content::UnsecuredData(ref crl_inner_data) = crl_inner_data.content else {
        log::error!("CRL does not contain any data");
        return;
    };
    let ctl_inner: c_its::asn::etsi_ts_102941_messages_ca::EtsiTs102941Data = match rasn::oer::decode(&crl_inner_data.0) {
        Ok(data) => data,
        Err(err) => {
            log::error!("Could not decode CRL inner data: {}", err);
            return;
        }
    };
    let c_its::asn::etsi_ts_102941_messages_ca::EtsiTs102941DataContent::certificateRevocationList(ref crl) = ctl_inner.content else {
        log::error!("CRL data does not a CRL element");
        return;
    };

    let this_update = c_its::security::certs::time32_to_utc(&crl.this_update);
    let next_update = c_its::security::certs::time32_to_utc(&crl.next_update);
    if this_update > state.now {
        log::error!("CRL issued in the future");
        return;
    }
    if next_update < state.now {
        log::error!("CRL expired");
        return;
    }
    
    log::info!("Got CRL for {}", state.root_ca_report.subject());

    let crl_file = state.ctl_data_dir.join(format!("crl-{}-{}.oer", state.root_ca_id8_hex, state.root_ca_report.subject()));
    if let Err(err) = std::fs::write(crl_file, &crl_inner_data.0) {
        panic!("Could not write CRL file: {}", err);
    }
}

fn main() {
    pretty_env_logger::init();

    let now = chrono::Utc::now();
    let ctl_data_dir = std::path::PathBuf::from_str("./ctl").unwrap();
    let client = reqwest::blocking::Client::builder()
        .user_agent(concat!("C-ITS Rust", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    for ctl_entry in ctl_data_dir.read_dir().unwrap() {
        let ctl_entry = ctl_entry.unwrap();
        if !ctl_entry.file_name().as_encoded_bytes().starts_with(b"root-") || !ctl_entry.file_name().as_encoded_bytes().ends_with(b".oer") {
            continue;
        }
        let root_ca_path = ctl_entry.path();
        let root_ca_meta_path = root_ca_path.with_extension("json");
        let root_ca_bytes = std::fs::read(&root_ca_path).expect("Unable to read root CA file");
        let root_ca_meta_bytes = std::fs::read(&root_ca_meta_path).expect("Unable to read root CA file");

        let root_ca = c_its::security::certs::Certificate::parse(&root_ca_bytes).unwrap();
        let root_ca_id8_hex = hex::encode_upper(root_ca.id8().unwrap());
        let root_ca_meta: CertMeta = serde_json::from_slice(&root_ca_meta_bytes).unwrap();
        let root_ca_report = root_ca.report().unwrap();

        let c_its::security::certs::CertificateSignature::SelfSigned { verifies } = root_ca_report.signature() else {
            log::error!("Root CA certificate does not have a self-signed signature");
            continue;
        };
        if !verifies {
            log::error!("Root CA certificate signature does not validate");
            continue;
        }

        let root_ca_dc = reqwest::Url::parse(&root_ca_meta.distribution_centre).unwrap();

        let mut security_store = c_its::security::SecurityStore::new();
        security_store.insert_cert(root_ca);

        let mut state = State {
            now,
            client: &client,
            ctl_data_dir: &ctl_data_dir,
            root_ca_id8_hex,
            root_ca_path,
            root_ca_meta,
            root_ca_report,
            security_store,
            root_ca_dc,
        };

        sync_ctl(&mut state);
        sync_crl(&mut state);
    }
}