use clap::Parser;

mod pki_certs;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    root_cert: std::path::PathBuf,
    #[arg(long)]
    root_key: std::path::PathBuf,
}

fn main() {
    let args = Args::parse();

    let root_cert = c_its::security::certs::Certificate::parse(&std::fs::read(&args.root_cert).unwrap()).unwrap();
    let root_key = c_its::security::crypto::PrivateKey::from_bytes_pem(&std::fs::read(&args.root_key).unwrap()).unwrap();

    let cert_info = pki_certs::CertInfo::collect_info("AA", true);
    let valid_from = chrono::Utc::now();
    let verification_private_key = cert_info.key_alg.generate_private_key();
    let encryption_private_key = cert_info.key_alg.generate_private_encryption_key();

    std::fs::create_dir_all("./pki-store/").unwrap();

    let tbs_cert = rasn_its::ieee1609dot2::ToBeSignedCertificate::builder()
        .id(rasn_its::ieee1609dot2::CertificateId::Name(
            rasn_its::ieee1609dot2::base_types::Hostname(cert_info.cert_name),
        ))
        .craca_id(rasn_its::ieee1609dot2::base_types::HashedId3(
            rasn::types::FixedOctetString::new([0, 0, 0]),
        ))
        .crl_series(rasn_its::ieee1609dot2::base_types::CrlSeries(0))
        .validity_period(rasn_its::ieee1609dot2::base_types::ValidityPeriod {
            start: c_its::security::certs::utc_to_time32(&valid_from),
            duration: rasn_its::ieee1609dot2::base_types::Duration::Years(cert_info.validity_duration_years),
        })
        .app_permissions(rasn_its::ieee1609dot2::base_types::SequenceOfPsidSsp(vec![].into()))
        .cert_issue_permissions(rasn_its::ieee1609dot2::SequenceOfPsidGroupPermissions(
            vec![rasn_its::ieee1609dot2::PsidGroupPermissions {
                min_chain_length: 1.into(),
                chain_length_range: 0.into(),
                subject_permissions: rasn_its::ieee1609dot2::SubjectPermissions::Explicit(
                    rasn_its::ieee1609dot2::base_types::SequenceOfPsidSspRange(pki_certs::ALL_APP_PERMS.to_vec().into()),
                ),
                ee_type: rasn_its::ieee1609dot2::EndEntityType(rasn::types::FixedBitString::new([
                    rasn_its::ieee1609dot2::EndEntityType::APP.into(),
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ])),
            }],
        ))
        .verify_key_indicator(rasn_its::ieee1609dot2::VerificationKeyIndicator::VerificationKey(
            verification_private_key.public_key().encode(),
        ))
        .encryption_key(encryption_private_key.public_key().encode_encryption().unwrap())
        .build()
        .unwrap();

    let cert = pki_certs::sign_cert(tbs_cert, &root_key, Some(&root_cert));
    let cert_report = cert.report().unwrap();
    let id8 = hex::encode_upper(cert_report.id8());
    println!("Generated AA certificate with ID8 {}", id8);

    std::fs::write(format!("./pki-store/aa-{}.oer", id8), cert.to_bytes()).unwrap();
    std::fs::write(format!("./pki-store/aa-{}-sig.key", id8), verification_private_key.as_bytes_pem()).unwrap();
    std::fs::write(format!("./pki-store/aa-{}-enc.key", id8), encryption_private_key.as_bytes_pem()).unwrap();
}
