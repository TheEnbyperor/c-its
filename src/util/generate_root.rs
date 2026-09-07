use elliptic_curve::Generate;

enum KeyAlg {
    P256,
    P384,
    BP256,
    BP384,
}

fn main() {
    let cert_name = inquire::Text::new("Name of the root").prompt().unwrap();
    let (key_alg, hash_alg) = match inquire::Select::new(
        "Algorithm for the root",
        vec![
            inquire::list_option::ListOption::new(0, "NIST P-256"),
            inquire::list_option::ListOption::new(1, "NIST P-384"),
            inquire::list_option::ListOption::new(2, "Brainpool 256r1"),
            inquire::list_option::ListOption::new(3, "Brainpool 384r1"),
        ],
    )
    .prompt()
    .unwrap()
    .index
    {
        0 => (KeyAlg::P256, c_its::security::crypto::HashAlgorithm::Sha256),
        1 => (KeyAlg::P384, c_its::security::crypto::HashAlgorithm::Sha384),
        2 => (
            KeyAlg::BP256,
            c_its::security::crypto::HashAlgorithm::Sha256,
        ),
        3 => (
            KeyAlg::BP384,
            c_its::security::crypto::HashAlgorithm::Sha384,
        ),
        _ => unreachable!(),
    };
    let validity_duration = inquire::CustomType::new("Validity duration in years")
        .with_default(5u16)
        .prompt()
        .unwrap();
    let valid_from = chrono::Utc::now();

    let private_key = match key_alg {
        KeyAlg::P256 => {
            c_its::security::crypto::PrivateKey::P256(p256::SecretKey::generate().into())
        }
        KeyAlg::P384 => {
            c_its::security::crypto::PrivateKey::P384(p384::SecretKey::generate().into())
        }
        KeyAlg::BP256 => {
            c_its::security::crypto::PrivateKey::BP256(bp256::r1::SecretKey::generate().into())
        }
        KeyAlg::BP384 => {
            c_its::security::crypto::PrivateKey::BP384(bp384::r1::SecretKey::generate().into())
        }
    };

    let tbs_cert = rasn_its::ieee1609dot2::ToBeSignedCertificate::builder()
        .id(rasn_its::ieee1609dot2::CertificateId::Name(
            rasn_its::ieee1609dot2::base_types::Hostname(cert_name),
        ))
        .craca_id(rasn_its::ieee1609dot2::base_types::HashedId3(
            rasn::types::FixedOctetString::new([0, 0, 0]),
        ))
        .crl_series(rasn_its::ieee1609dot2::base_types::CrlSeries(0))
        .validity_period(rasn_its::ieee1609dot2::base_types::ValidityPeriod {
            start: c_its::security::certs::utc_to_time32(&valid_from),
            duration: rasn_its::ieee1609dot2::base_types::Duration::Years(validity_duration),
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
                    rasn_its::ieee1609dot2::base_types::SequenceOfPsidSspRange(
                        vec![
                            // All CAM messages
                            rasn_its::ieee1609dot2::base_types::PsidSspRange {
                                psid: rasn_its::ieee1609dot2::base_types::Psid(
                                    c_its::security::perms::PSID_CAM.clone(),
                                ),
                                ssp_range: Some(
                                    rasn_its::ieee1609dot2::base_types::SspRange::BitmapSspRange(
                                        rasn_its::ieee1609dot2::base_types::BitmapSspRange {
                                            ssp_value: [0x01, 0xFF, 0xFC].into(),
                                            ssp_bitmask: [0xFF, 0x00, 0x03].into(),
                                        },
                                    ),
                                ),
                            },
                            // All DENM messages
                            rasn_its::ieee1609dot2::base_types::PsidSspRange {
                                psid: rasn_its::ieee1609dot2::base_types::Psid(
                                    c_its::security::perms::PSID_DENM.clone(),
                                ),
                                ssp_range: Some(
                                    rasn_its::ieee1609dot2::base_types::SspRange::BitmapSspRange(
                                        rasn_its::ieee1609dot2::base_types::BitmapSspRange {
                                            ssp_value: [0x02, 0xFF, 0xFF, 0xFF, 0xF0].into(),
                                            ssp_bitmask: [0xFF, 0x00, 0x00, 0x00, 0xF].into(),
                                        },
                                    ),
                                ),
                            },
                            // All TLM messages
                            rasn_its::ieee1609dot2::base_types::PsidSspRange {
                                psid: rasn_its::ieee1609dot2::base_types::Psid(
                                    c_its::security::perms::PSID_TLM.clone(),
                                ),
                                ssp_range: Some(
                                    rasn_its::ieee1609dot2::base_types::SspRange::BitmapSspRange(
                                        rasn_its::ieee1609dot2::base_types::BitmapSspRange {
                                            ssp_value: [0x01, 0xE0].into(),
                                            ssp_bitmask: [0xFF, 0x1F].into(),
                                        },
                                    ),
                                ),
                            },
                            // All RLT messages
                            rasn_its::ieee1609dot2::base_types::PsidSspRange {
                                psid: rasn_its::ieee1609dot2::base_types::Psid(
                                    c_its::security::perms::PSID_RLT.clone(),
                                ),
                                ssp_range: Some(
                                    rasn_its::ieee1609dot2::base_types::SspRange::BitmapSspRange(
                                        rasn_its::ieee1609dot2::base_types::BitmapSspRange {
                                            ssp_value: [0x01, 0xC0].into(),
                                            ssp_bitmask: [0xFF, 0x3F].into(),
                                        },
                                    ),
                                ),
                            },
                            // All IVIM messages
                            rasn_its::ieee1609dot2::base_types::PsidSspRange {
                                psid: rasn_its::ieee1609dot2::base_types::Psid(
                                    c_its::security::perms::PSID_IVIM.clone(),
                                ),
                                ssp_range: Some(
                                    rasn_its::ieee1609dot2::base_types::SspRange::BitmapSspRange(
                                        rasn_its::ieee1609dot2::base_types::BitmapSspRange {
                                            ssp_value: [0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
                                                .into(),
                                            ssp_bitmask: [0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
                                                .into(),
                                        },
                                    ),
                                ),
                            },
                            // All TLCReq messages
                            rasn_its::ieee1609dot2::base_types::PsidSspRange {
                                psid: rasn_its::ieee1609dot2::base_types::Psid(
                                    c_its::security::perms::PSID_TLC_REQ.clone(),
                                ),
                                ssp_range: Some(
                                    rasn_its::ieee1609dot2::base_types::SspRange::BitmapSspRange(
                                        rasn_its::ieee1609dot2::base_types::BitmapSspRange {
                                            ssp_value: [0x02, 0xFF, 0xFF, 0xE0].into(),
                                            ssp_bitmask: [0xFF, 0x00, 0x00, 0x1F].into(),
                                        },
                                    ),
                                ),
                            },
                            // All TLCStatus messages
                            rasn_its::ieee1609dot2::base_types::PsidSspRange {
                                psid: rasn_its::ieee1609dot2::base_types::Psid(
                                    c_its::security::perms::PSID_TLC_STATUS.clone(),
                                ),
                                ssp_range: Some(
                                    rasn_its::ieee1609dot2::base_types::SspRange::BitmapSspRange(
                                        rasn_its::ieee1609dot2::base_types::BitmapSspRange {
                                            ssp_value: [0x01].into(),
                                            ssp_bitmask: [0xFF].into(),
                                        },
                                    ),
                                ),
                            },
                            // All VRU messages
                            rasn_its::ieee1609dot2::base_types::PsidSspRange {
                                psid: rasn_its::ieee1609dot2::base_types::Psid(
                                    c_its::security::perms::PSID_VRU.clone(),
                                ),
                                ssp_range: Some(
                                    rasn_its::ieee1609dot2::base_types::SspRange::BitmapSspRange(
                                        rasn_its::ieee1609dot2::base_types::BitmapSspRange {
                                            ssp_value: [0x01].into(),
                                            ssp_bitmask: [0xFF].into(),
                                        },
                                    ),
                                ),
                            },
                            // All CP messages
                            rasn_its::ieee1609dot2::base_types::PsidSspRange {
                                psid: rasn_its::ieee1609dot2::base_types::Psid(
                                    c_its::security::perms::PSID_CP.clone(),
                                ),
                                ssp_range: Some(
                                    rasn_its::ieee1609dot2::base_types::SspRange::BitmapSspRange(
                                        rasn_its::ieee1609dot2::base_types::BitmapSspRange {
                                            ssp_value: [0x01].into(),
                                            ssp_bitmask: [0xFF].into(),
                                        },
                                    ),
                                ),
                            },
                            // All GN Mgmt messages
                            rasn_its::ieee1609dot2::base_types::PsidSspRange {
                                psid: rasn_its::ieee1609dot2::base_types::Psid(
                                    c_its::security::perms::PSID_GN_MGMT.clone(),
                                ),
                                ssp_range: Some(rasn_its::ieee1609dot2::base_types::SspRange::All(())),
                            },
                            // All SA messages
                            rasn_its::ieee1609dot2::base_types::PsidSspRange {
                                psid: rasn_its::ieee1609dot2::base_types::Psid(
                                    c_its::security::perms::PSID_SA.clone(),
                                ),
                                ssp_range: Some(rasn_its::ieee1609dot2::base_types::SspRange::All(())),
                            },
                        ]
                        .into(),
                    ),
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

    let tbs_bytes = rasn::oer::encode(&tbs_cert).unwrap();
    let signature = private_key.sign(hash_alg, &tbs_bytes, None).unwrap();

    let raw_cert = rasn_its::ts103097::EtsiTs103097Certificate::try_from(
        rasn_its::ieee1609dot2::Certificate::from(
            rasn_its::ieee1609dot2::ExplicitCertificate::new(
                rasn_its::ieee1609dot2::CertificateBase {
                    version: 3,
                    r#type: rasn_its::ieee1609dot2::CertificateType::Explicit,
                    issuer: rasn_its::ieee1609dot2::IssuerIdentifier::VSelf(hash_alg.into()),
                    to_be_signed: tbs_cert,
                    signature: Some(signature.as_signature()),
                },
            )
            .unwrap(),
        ),
    )
    .unwrap();

    let cert = c_its::security::certs::Certificate::new(&raw_cert);
    let cert_report = cert.report().unwrap();
    let id8 = hex::encode_upper(cert_report.id8());
    println!("Generated root certificate with ID8 {}", id8);

    std::fs::write(format!("{}.oer", id8), cert.to_bytes()).unwrap();
    std::fs::write(format!("{}.key", id8), private_key.as_bytes_pem()).unwrap();
}
