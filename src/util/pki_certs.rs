use lazy_static::lazy_static;

pub enum KeyAlg {
    P256,
    P384,
    BP256,
    BP384,
}

impl KeyAlg {
    pub fn generate_private_key(&self) -> c_its::security::crypto::PrivateKey {
        use elliptic_curve::Generate;
        match self {
            Self::P256 => {
                c_its::security::crypto::PrivateKey::P256(p256::SecretKey::generate().into())
            }
            Self::P384 => {
                c_its::security::crypto::PrivateKey::P384(p384::SecretKey::generate().into())
            }
            Self::BP256 => {
                c_its::security::crypto::PrivateKey::BP256(bp256::r1::SecretKey::generate().into())
            }
            Self::BP384 => {
                c_its::security::crypto::PrivateKey::BP384(bp384::r1::SecretKey::generate().into())
            }
        }
    }

    pub fn generate_private_encryption_key(&self) -> c_its::security::crypto::PrivateKey {
        use elliptic_curve::Generate;
        match self {
            Self::P256 | Self::P384 => {
                c_its::security::crypto::PrivateKey::P256(p256::SecretKey::generate().into())
            }
            Self::BP256 | Self::BP384 => {
                c_its::security::crypto::PrivateKey::BP256(bp256::r1::SecretKey::generate().into())
            }
        }
    }
}

pub struct CertInfo {
    pub cert_name: String,
    pub key_alg: KeyAlg,
    pub validity_duration_years: u16,
}

impl CertInfo {
    pub fn collect_info(cert_type: &str, need_name: bool) -> Self {
        let cert_name = if need_name {
            inquire::Text::new(&format!("Name of the {} certificate", cert_type))
                .prompt()
                .unwrap()
        } else {
            String::default()
        };
        let key_alg = match inquire::Select::new(
            &format!("Algorithm for the {} certificate", cert_type),
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
            0 => KeyAlg::P256,
            1 => KeyAlg::P384,
            2 => KeyAlg::BP256,
            3 => KeyAlg::BP384,
            _ => unreachable!(),
        };
        let validity_duration_years = inquire::CustomType::new("Validity duration in years")
            .with_default(5u16)
            .prompt()
            .unwrap();

        Self {
            cert_name,
            key_alg,
            validity_duration_years,
        }
    }
}

pub fn sign_cert(
    tbs_cert: rasn_its::ieee1609dot2::ToBeSignedCertificate,
    signing_key: &c_its::security::crypto::PrivateKey,
    issuing_certificate: Option<&c_its::security::certs::Certificate>,
) -> c_its::security::certs::Certificate<'static> {
    let tbs_bytes = rasn::oer::encode(&tbs_cert).unwrap();
    let signature = signing_key.sign(&tbs_bytes, issuing_certificate).unwrap();
    let raw_cert = rasn_its::ts103097::EtsiTs103097Certificate::try_from(
        rasn_its::ieee1609dot2::Certificate::from(
            rasn_its::ieee1609dot2::ExplicitCertificate::new(
                rasn_its::ieee1609dot2::CertificateBase {
                    version: 3,
                    r#type: rasn_its::ieee1609dot2::CertificateType::Explicit,
                    issuer: if let Some(issuer) = issuing_certificate {
                        match signing_key.hash_algorithm() {
                            c_its::security::crypto::HashAlgorithm::Sha256 => {
                                rasn_its::ieee1609dot2::IssuerIdentifier::Sha256AndDigest(
                                    rasn_its::ieee1609dot2::base_types::HashedId8(
                                        issuer.id8().unwrap_or_default().into(),
                                    )
                                )
                            }
                            c_its::security::crypto::HashAlgorithm::Sha384 => {
                                rasn_its::ieee1609dot2::IssuerIdentifier::Sha384AndDigest(
                                    rasn_its::ieee1609dot2::base_types::HashedId8(
                                        issuer.id8().unwrap_or_default().into(),
                                    )
                                )
                            }
                            c_its::security::crypto::HashAlgorithm::Sm3 => {
                                rasn_its::ieee1609dot2::IssuerIdentifier::Sm3AndDigest(
                                    rasn_its::ieee1609dot2::base_types::HashedId8(
                                        issuer.id8().unwrap_or_default().into(),
                                    )
                                )
                            }
                        }
                    } else {
                        rasn_its::ieee1609dot2::IssuerIdentifier::VSelf(signing_key.hash_algorithm().into())
                    },
                    to_be_signed: tbs_cert,
                    signature: Some(signature.as_signature()),
                },
            )
            .unwrap(),
        ),
    )
    .unwrap();
    let cert = c_its::security::certs::Certificate::new_owned(raw_cert);
    cert
}

pub fn sign_message<T: rasn::Decode>(
    data: &[u8],
    timestamp: &chrono::DateTime<chrono::Utc>,
    signing_key: &c_its::security::crypto::PrivateKey,
    certificate: &c_its::security::certs::Certificate,
) -> rasn_its::ts103097::EtsiTs103097DataSigned<T> {
    let tbs = rasn_its::ieee1609dot2::ToBeSignedData {
        header_info: rasn_its::ieee1609dot2::HeaderInfo::builder()
            .psid(rasn_its::ieee1609dot2::base_types::Psid(c_its::security::perms::PSID_CTL.clone()))
            .generation_time(c_its::security::certs::utc_to_time64(timestamp))
            .build(),
        payload: rasn_its::ieee1609dot2::SignedDataPayload::builder()
            .data(rasn_its::ieee1609dot2::Ieee1609Dot2Data {
                protocol_version: 3,
                content: rasn_its::ieee1609dot2::Ieee1609Dot2Content::UnsecuredData(
                    rasn_its::ieee1609dot2::base_types::Opaque(data.into())
                )
            })
            .build().unwrap(),
    };
    let tbs_bytes = rasn::oer::encode(&tbs).unwrap();
    let signature = signing_key.sign(&tbs_bytes, Some(&certificate)).unwrap();
    rasn_its::ts103097::EtsiTs103097DataSigned::<T>::try_from(
        rasn_its::ts103097::EtsiTs103097Data::try_from(rasn_its::ieee1609dot2::Ieee1609Dot2Data {
            protocol_version: 3,
            content: rasn_its::ieee1609dot2::Ieee1609Dot2Content::SignedData(Box::new(rasn_its::ieee1609dot2::SignedData {
                hash_id: signing_key.hash_algorithm().into(),
                tbs_data: tbs,
                signer: rasn_its::ieee1609dot2::SignerIdentifier::Certificate(
                    rasn_its::ieee1609dot2::SequenceOfCertificate(vec![(**certificate.as_cert()).clone()])
                ),
                signature: signature.as_signature(),
            })),
        }).unwrap()
    ).unwrap()
}

lazy_static! {
    pub static ref ALL_APP_PERMS: Vec<rasn_its::ieee1609dot2::base_types::PsidSspRange> = {
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
    };
}
