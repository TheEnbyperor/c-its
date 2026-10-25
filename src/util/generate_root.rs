mod pki_certs;

fn main() {
    let cert_info = pki_certs::CertInfo::collect_info("root", true);
    let valid_from = chrono::Utc::now();
    let private_key = cert_info.key_alg.generate_private_key();

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
        .app_permissions(rasn_its::ieee1609dot2::base_types::SequenceOfPsidSsp(
            vec![
                rasn_its::ieee1609dot2::base_types::PsidSsp {
                    psid: rasn_its::ieee1609dot2::base_types::Psid(
                        c_its::security::perms::PSID_CRL.clone(),
                    ),
                    ssp: Some(
                        rasn_its::ieee1609dot2::base_types::ServiceSpecificPermissions::BitmapSsp(
                            rasn_its::ieee1609dot2::base_types::BitmapSsp([0x01].into()),
                        ),
                    ),
                },
                rasn_its::ieee1609dot2::base_types::PsidSsp {
                    psid: rasn_its::ieee1609dot2::base_types::Psid(
                        c_its::security::perms::PSID_CTL.clone(),
                    ),
                    ssp: Some(
                        rasn_its::ieee1609dot2::base_types::ServiceSpecificPermissions::BitmapSsp(
                            c_its::security::perms::CertificateTrustListPermissions::new(
                                false, false, true, true, true,
                            )
                            .as_bitmap(),
                        ),
                    ),
                },
            ]
            .into(),
        ))
        .cert_issue_permissions(rasn_its::ieee1609dot2::SequenceOfPsidGroupPermissions(
            vec![rasn_its::ieee1609dot2::PsidGroupPermissions {
                min_chain_length: 2.into(),
                chain_length_range: 0.into(),
                subject_permissions: rasn_its::ieee1609dot2::SubjectPermissions::Explicit(
                    rasn_its::ieee1609dot2::base_types::SequenceOfPsidSspRange(pki_certs::ALL_APP_PERMS.to_vec().into())
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
        .verify_key_indicator(
            rasn_its::ieee1609dot2::VerificationKeyIndicator::VerificationKey(
                private_key.public_key().encode(),
            ),
        )
        .build()
        .unwrap();

    let cert = pki_certs::sign_cert(tbs_cert, &private_key, None);
    let cert_report = cert.report::<c_its::security::std_crypto::StdCrypto>().unwrap();
    let id8 = hex::encode_upper(cert_report.id8());
    println!("Generated root certificate with ID8 {}", id8);

    std::fs::write(format!("./pki-store/root-{}.oer", id8), cert.to_bytes()).unwrap();
    std::fs::write(format!("./pki-store/root-{}.key", id8), private_key.as_bytes_pem()).unwrap();
}
