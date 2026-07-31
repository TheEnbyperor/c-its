use alloc::string::ToString;
use core::fmt::Display;
use ecdsa::signature::digest::Digest;

pub fn time32_to_utc(
    time32: &rasn_its::ieee1609dot2::base_types::Time32,
) -> chrono::DateTime<chrono::Utc> {
    crate::util::chrono_from_tai(
        &crate::geo_networking::GnTaiTime::new(time32.0 as i64, 0).unwrap(),
    )
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Certificate<'a>(
    pub(crate) alloc::borrow::Cow<'a, rasn_its::ts103097::EtsiTs103097Certificate>,
);

impl Certificate<'_> {
    pub fn new(cert: &rasn_its::ts103097::EtsiTs103097Certificate) -> Certificate<'_> {
        Certificate(alloc::borrow::Cow::Borrowed(cert))
    }

    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        let cert: rasn_its::ts103097::EtsiTs103097Certificate =
            rasn::oer::decode(data).map_err(|_| "failed to decode certificate")?;
        Ok(Self(alloc::borrow::Cow::Owned(cert)))
    }

    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        rasn::oer::encode(&self.0).unwrap()
    }

    pub(crate) fn to_owned(&self) -> Certificate<'static> {
        Certificate(alloc::borrow::Cow::Owned(
            <rasn_its::ts103097::EtsiTs103097Certificate as Clone>::clone(&self.0),
        ))
    }

    pub(crate) fn public_key(&self) -> Result<super::crypto::PublicKey, &'static str> {
        if self.0.r#type == rasn_its::ieee1609dot2::CertificateType::Implicit {
            return Err("implicit certificates are not supported");
        }

        let rasn_its::ieee1609dot2::VerificationKeyIndicator::VerificationKey(public_key) =
            &self.0.to_be_signed.verify_key_indicator
        else {
            return Err("implicit certificates are not supported");
        };

        super::crypto::PublicKey::parse(public_key)
    }

    pub fn id8(&self) -> Option<[u8; 8]> {
        let d = rasn::oer::encode(&self.0).ok()?;
        match &self.0.to_be_signed.verify_key_indicator {
            rasn_its::ieee1609dot2::VerificationKeyIndicator::ReconstructionValue(_) => {
                match &self.0.issuer {
                    rasn_its::ieee1609dot2::IssuerIdentifier::Sha256AndDigest(_) => Some(
                        <[u8; 8]>::try_from(&sha2::Sha256::digest(&d).as_slice()[24..32]).unwrap(),
                    ),
                    rasn_its::ieee1609dot2::IssuerIdentifier::Sm3AndDigest(_) => {
                        Some(<[u8; 8]>::try_from(&sm3::Sm3::digest(&d).as_slice()[24..32]).unwrap())
                    }
                    _ => None,
                }
            }
            rasn_its::ieee1609dot2::VerificationKeyIndicator::VerificationKey(vk) => match vk {
                rasn_its::ieee1609dot2::base_types::PublicVerificationKey::EcdsaNistP256(_)
                | rasn_its::ieee1609dot2::base_types::PublicVerificationKey::EcdsaBrainpoolP256r1(
                    _,
                ) => {
                    Some(<[u8; 8]>::try_from(&sha2::Sha256::digest(&d).as_slice()[24..32]).unwrap())
                }
                rasn_its::ieee1609dot2::base_types::PublicVerificationKey::EcdsaNistP384(_)
                | rasn_its::ieee1609dot2::base_types::PublicVerificationKey::EcdsaBrainpoolP384r1(
                    _,
                ) => {
                    Some(<[u8; 8]>::try_from(&sha2::Sha384::digest(&d).as_slice()[40..48]).unwrap())
                }
                rasn_its::ieee1609dot2::base_types::PublicVerificationKey::EcsigSm2(_) => {
                    Some(<[u8; 8]>::try_from(&sm3::Sm3::digest(&d).as_slice()[24..32]).unwrap())
                }
                _ => None,
            },
            _ => None,
        }
    }

    pub fn validity_period(
        &self,
    ) -> (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) {
        let valid_from = time32_to_utc(&self.0.to_be_signed.validity_period.start);
        let duration = match self.0.to_be_signed.validity_period.duration {
            rasn_its::ieee1609dot2::base_types::Duration::Microseconds(us) => {
                chrono::Duration::microseconds(us as i64)
            }
            rasn_its::ieee1609dot2::base_types::Duration::Milliseconds(ms) => {
                chrono::Duration::milliseconds(ms as i64)
            }
            rasn_its::ieee1609dot2::base_types::Duration::Seconds(s) => {
                chrono::Duration::seconds(s as i64)
            }
            rasn_its::ieee1609dot2::base_types::Duration::Minutes(m) => {
                chrono::Duration::minutes(m as i64)
            }
            rasn_its::ieee1609dot2::base_types::Duration::Hours(h) => {
                chrono::Duration::hours(h as i64)
            }
            rasn_its::ieee1609dot2::base_types::Duration::SixtyHours(h) => {
                chrono::Duration::hours(h as i64 * 60)
            }
            rasn_its::ieee1609dot2::base_types::Duration::Years(y) => {
                chrono::Duration::seconds(y as i64 * 31_556_952)
            }
        };
        (valid_from, valid_from + duration)
    }

    pub fn report(&self) -> Result<CertificateReport, &'static str> {
        let certificate_validity = self.validity_period();
        let tbs_bytes = rasn::oer::encode(&self.0.to_be_signed).unwrap();
        let signature = self
            .0
            .signature
            .as_ref()
            .map(|s| super::crypto::Signature::parse(s))
            .transpose()?;
        let public_key = self.public_key()?;
        let encoded = match rasn::oer::encode(&self.0) {
            Ok(encoded) => encoded,
            Err(_) => return Err("failed to encode certificate to bytes"),
        };
        Ok(CertificateReport {
            id8: self.id8().unwrap_or_default(),
            subject: match &self.0.to_be_signed.id {
                rasn_its::ieee1609dot2::CertificateId::None(()) => CertificateSubject::None,
                rasn_its::ieee1609dot2::CertificateId::Name(hn) => CertificateSubject::Hostname {
                    hostname: hn.0.to_string(),
                },
                rasn_its::ieee1609dot2::CertificateId::BinaryId(id) => {
                    CertificateSubject::Binary { id: id.to_vec() }
                }
                _ => unreachable!(),
            },
            valid_from: certificate_validity.0,
            valid_until: certificate_validity.1,
            app_permissions: match &self.0.to_be_signed.app_permissions {
                Some(p) => p.0.iter().map(Into::into).collect(),
                None => alloc::vec::Vec::new(),
            },
            cert_issue_permissions: match &self.0.to_be_signed.cert_issue_permissions {
                Some(p) => p.0.iter().map(Into::into).collect(),
                None => alloc::vec::Vec::new(),
            },
            cert_request_permissions: match &self.0.to_be_signed.cert_request_permissions {
                Some(p) => p.0.iter().map(Into::into).collect(),
                None => alloc::vec::Vec::new(),
            },
            signature: if let Some(signature) = signature {
                match &self.0.issuer {
                    rasn_its::ieee1609dot2::IssuerIdentifier::VSelf(h) => match h.try_into() {
                        Ok(h) => CertificateSignature::SelfSigned {
                            verifies: signature.verify(&self.public_key()?, h, &tbs_bytes, None),
                        },
                        Err(_) => CertificateSignature::SelfSigned { verifies: false },
                    },
                    rasn_its::ieee1609dot2::IssuerIdentifier::Sha256AndDigest(id) => {
                        CertificateSignature::Parent {
                            id8: *id.0,
                            hash_alg: super::crypto::HashAlgorithm::Sha256,
                            tbs_bytes,
                            signature,
                        }
                    }
                    rasn_its::ieee1609dot2::IssuerIdentifier::Sha384AndDigest(id) => {
                        CertificateSignature::Parent {
                            id8: *id.0,
                            hash_alg: super::crypto::HashAlgorithm::Sha384,
                            tbs_bytes,
                            signature,
                        }
                    }
                    rasn_its::ieee1609dot2::IssuerIdentifier::Sm3AndDigest(id) => {
                        CertificateSignature::Parent {
                            id8: *id.0,
                            hash_alg: super::crypto::HashAlgorithm::Sm3,
                            tbs_bytes,
                            signature,
                        }
                    }
                    _ => CertificateSignature::Unknown,
                }
            } else {
                CertificateSignature::Unsigned
            },
            public_key,
            encoded,
        })
    }
}

impl PartialOrd for Certificate<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        match (&self.0.to_be_signed.id, &other.0.to_be_signed.id) {
            (
                rasn_its::ieee1609dot2::CertificateId::None(()),
                rasn_its::ieee1609dot2::CertificateId::None(()),
            ) => Some(core::cmp::Ordering::Equal),
            (rasn_its::ieee1609dot2::CertificateId::None(()), _) => {
                Some(core::cmp::Ordering::Greater)
            }
            (_, rasn_its::ieee1609dot2::CertificateId::None(())) => Some(core::cmp::Ordering::Less),
            (
                rasn_its::ieee1609dot2::CertificateId::BinaryId(s),
                rasn_its::ieee1609dot2::CertificateId::BinaryId(o),
            ) => s.partial_cmp(o),
            (rasn_its::ieee1609dot2::CertificateId::BinaryId(_), _) => {
                Some(core::cmp::Ordering::Greater)
            }
            (_, rasn_its::ieee1609dot2::CertificateId::BinaryId(_)) => {
                Some(core::cmp::Ordering::Less)
            }
            (
                rasn_its::ieee1609dot2::CertificateId::Name(s),
                rasn_its::ieee1609dot2::CertificateId::Name(o),
            ) => s.partial_cmp(o),
            (rasn_its::ieee1609dot2::CertificateId::Name(_), _) => {
                Some(core::cmp::Ordering::Greater)
            }
            (_, rasn_its::ieee1609dot2::CertificateId::Name(_)) => Some(core::cmp::Ordering::Less),
            (
                rasn_its::ieee1609dot2::CertificateId::LinkageData(s),
                rasn_its::ieee1609dot2::CertificateId::LinkageData(o),
            ) => s.linkage_value.partial_cmp(&o.linkage_value),
            (rasn_its::ieee1609dot2::CertificateId::LinkageData(_), _) => {
                Some(core::cmp::Ordering::Greater)
            }
            (_, rasn_its::ieee1609dot2::CertificateId::LinkageData(_)) => {
                Some(core::cmp::Ordering::Less)
            }
            (_, _) => None,
        }
    }
}

impl Ord for Certificate<'_> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.partial_cmp(other)
            .unwrap_or(core::cmp::Ordering::Equal)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CRL<'a>(
    pub(crate) alloc::borrow::Cow<'a, crate::asn::etsi_ts102941_trust_lists::ToBeSignedCrl>,
);

impl CRL<'_> {
    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        let data: crate::asn::etsi_ts_102941_messages_ca::EtsiTs102941Data =
            rasn::oer::decode(data).map_err(|_| "failed to decode CRL")?;
        let crate::asn::etsi_ts_102941_messages_ca::EtsiTs102941DataContent::certificateRevocationList(crl) = data.content else {
            return Err("CRL data does not a CRL element");
        };
        Ok(Self(alloc::borrow::Cow::Owned(crl)))
    }

    pub fn is_revoked(&self, id8: [u8; 8]) -> bool {
        self.0.entries.iter().find(|e| *e.0.0 == id8).is_some()
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct CertificateReport {
    #[serde(serialize_with = "crate::util::serialize_bytes_hex")]
    id8: [u8; 8],
    subject: CertificateSubject,
    valid_from: chrono::DateTime<chrono::Utc>,
    valid_until: chrono::DateTime<chrono::Utc>,
    app_permissions: alloc::vec::Vec<super::perms::AppPermission>,
    cert_issue_permissions: alloc::vec::Vec<CertPermission>,
    cert_request_permissions: alloc::vec::Vec<CertPermission>,
    signature: CertificateSignature,
    public_key: super::crypto::PublicKey,
    #[serde(skip_serializing)]
    encoded: alloc::vec::Vec<u8>,
}

impl CertificateReport {
    pub fn id8(&self) -> [u8; 8] {
        self.id8
    }

    pub fn subject(&self) -> &CertificateSubject {
        &self.subject
    }

    pub fn valid_from(&self) -> &chrono::DateTime<chrono::Utc> {
        &self.valid_from
    }

    pub fn valid_until(&self) -> &chrono::DateTime<chrono::Utc> {
        &self.valid_until
    }

    pub fn app_permissions(&self) -> &[super::perms::AppPermission] {
        &self.app_permissions
    }
    pub fn cert_issue_permissions(&self) -> &[CertPermission] {
        &self.cert_issue_permissions
    }

    pub fn signature(&self) -> &CertificateSignature {
        &self.signature
    }

    pub fn public_key(&self) -> &super::crypto::PublicKey {
        &self.public_key
    }

    pub(crate) fn app_permissions_authorized_by(
        &self,
        issuer: &CertificateReport,
        chain_length: u64,
    ) -> bool {
        self.app_permissions.iter().all(|app_permission| {
            issuer.authorizes_app_permission(app_permission.into(), chain_length)
        })
    }

    fn authorizes_app_permission(
        &self,
        app_permission: RawAppPermission<'_>,
        chain_length: u64,
    ) -> bool {
        let contains_psid_explicitly = self
            .cert_request_permissions
            .iter()
            .any(|permission| permission.subject_permissions.contains_psid_explicitly(app_permission.psid()));
        self.cert_issue_permissions.iter().any(|permission| {
            permission.end_entity_authorization
                && permission.chain_length.0.contains(&chain_length)
                && permission
                    .subject_permissions
                    .authorizes(app_permission, contains_psid_explicitly)
        })
    }

    pub(crate) fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    pub fn get_cam_permission(&self) -> Option<&super::perms::CAMPermissions> {
        self.app_permissions
            .iter()
            .filter_map(|p| match p {
                super::perms::AppPermission::CAM(c) => Some(c),
                _ => None,
            })
            .next()
    }

    pub fn get_denm_permission(&self) -> Option<&super::perms::DENMPermissions> {
        self.app_permissions
            .iter()
            .filter_map(|p| match p {
                super::perms::AppPermission::DENM(c) => Some(c),
                _ => None,
            })
            .next()
    }

    pub fn get_rlt_permission(&self) -> Option<&super::perms::RLTPermissions> {
        self.app_permissions
            .iter()
            .filter_map(|p| match p {
                super::perms::AppPermission::RLT(c) => Some(c),
                _ => None,
            })
            .next()
    }

    pub fn get_ivim_permission(&self) -> Option<&super::perms::IVIMPermissions> {
        self.app_permissions
            .iter()
            .filter_map(|p| match p {
                super::perms::AppPermission::IVIM(c) => Some(c),
                _ => None,
            })
            .next()
    }

    pub fn get_tlc_req_permission(&self) -> Option<&super::perms::TlcReqPermissions> {
        self.app_permissions
            .iter()
            .filter_map(|p| match p {
                super::perms::AppPermission::TlcReq(c) => Some(c),
                _ => None,
            })
            .next()
    }

    pub fn get_tlm_permission(&self) -> Option<&super::perms::TLMPermissions> {
        self.app_permissions
            .iter()
            .filter_map(|p| match p {
                super::perms::AppPermission::TLM(c) => Some(c),
                _ => None,
            })
            .next()
    }

    pub fn get_ctl_permission(&self) -> Option<&super::perms::CertificateTrustListPermissions> {
        self.app_permissions
            .iter()
            .filter_map(|p| match p {
                super::perms::AppPermission::CertificateTrustList(c) => Some(c),
                _ => None,
            })
            .next()
    }

    pub fn has_tlc_status_permission(&self) -> bool {
        for p in self.app_permissions.iter() {
            if let super::perms::AppPermission::TlcStatus(_) = p {
                return true;
            }
        }
        false
    }

    pub fn has_crl_permission(&self) -> bool {
        for p in self.app_permissions.iter() {
            if let super::perms::AppPermission::CertificateTrustList(_) = p {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Clone, PartialOrd, Ord)]
#[serde(tag = "type")]
pub enum CertificateSignature {
    #[serde(rename = "unsigned")]
    Unsigned,
    #[serde(rename = "unknown")]
    Unknown,
    #[serde(rename = "self_signed")]
    SelfSigned { verifies: bool },
    #[serde(rename = "parent")]
    Parent {
        #[serde(serialize_with = "crate::util::serialize_bytes_hex")]
        id8: [u8; 8],
        hash_alg: super::crypto::HashAlgorithm,
        #[serde(skip_serializing)]
        tbs_bytes: alloc::vec::Vec<u8>,
        #[serde(skip_serializing)]
        signature: super::crypto::Signature,
    },
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Clone, PartialOrd, Ord)]
#[serde(tag = "type")]
pub enum CertificateSubject {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "hostname")]
    Hostname { hostname: alloc::string::String },
    #[serde(rename = "binary")]
    Binary {
        #[serde(serialize_with = "crate::util::serialize_bytes")]
        id: alloc::vec::Vec<u8>,
    },
}

impl Display for CertificateSubject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Hostname { hostname } => write!(f, "{}", hostname),
            Self::Binary { id } => write!(f, "0x{}", hex::encode(id)),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, PartialOrd, Ord)]
pub(super) enum RawAppPermission<'a> {
    Bitmap {
        psid: super::perms::ProviderService,
        data: &'a [u8],
    },
    Opaque {
        psid: super::perms::ProviderService,
        data: &'a [u8],
    },
    Unsupported {
        psid: super::perms::ProviderService,
    },
}

impl RawAppPermission<'_> {
    fn psid(&self) -> super::perms::ProviderService {
        match self {
            Self::Bitmap { psid, .. } | Self::Opaque { psid, .. } | Self::Unsupported { psid } => {
                *psid
            }
        }
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct CertPermission {
    chain_length: ChainLength,
    end_entity_authorization: bool,
    end_entity_enrollment: bool,
    subject_permissions: CertSubjectPermissions,
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Clone)]
pub struct ChainLength(core::ops::RangeInclusive<u64>);

impl core::cmp::Ord for ChainLength {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0
            .start()
            .cmp(&other.0.start())
            .then_with(|| self.0.end().cmp(&other.0.end()))
    }
}

impl core::cmp::PartialOrd for ChainLength {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Clone, PartialOrd, Ord)]
#[serde(tag = "type")]
pub enum CertSubjectPermissions {
    #[serde(rename = "all")]
    All {},
    #[serde(rename = "explicit")]
    Explicit {
        permissions: alloc::vec::Vec<CertSubjectPermission>,
    },
    #[serde(rename = "Unknown")]
    Unknown {},
}

impl CertSubjectPermissions {
    fn contains_psid_explicitly(&self, psid: super::perms::ProviderService) -> bool {
        match self {
            Self::Explicit { permissions } => {
                permissions.iter().any(|permission| permission.psid == psid)
            }
            Self::All {} | Self::Unknown {} => false,
        }
    }

    fn authorizes(
        &self,
        app_permission: RawAppPermission<'_>,
        contains_psid_explicitly: bool,
    ) -> bool {
        match self {
            Self::All {} => !contains_psid_explicitly,
            Self::Explicit { permissions } => permissions.iter().any(|permission| {
                permission.psid == app_permission.psid()
                    && permission.auth.authorizes(app_permission)
            }),
            Self::Unknown {} => false,
        }
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct CertSubjectPermission {
    psid: super::perms::ProviderService,
    auth: CertSubjectAuthorization,
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Clone, PartialOrd, Ord)]
#[serde(tag = "type")]
pub enum CertSubjectAuthorization {
    #[serde(rename = "all")]
    All {},
    #[serde(rename = "bitmap")]
    Bitmap {
        #[serde(serialize_with = "crate::util::serialize_bytes_hex")]
        subordinate_may_have: alloc::vec::Vec<u8>,
        #[serde(serialize_with = "crate::util::serialize_bytes_hex")]
        subordinate_must_have: alloc::vec::Vec<u8>,
    },
    #[serde(rename = "opaque")]
    Opaque {
        data: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    },
    #[serde(rename = "unsupported")]
    Unsupported {},
}

impl CertSubjectAuthorization {
    fn authorizes(&self, app_permission: RawAppPermission<'_>) -> bool {
        match (self, app_permission) {
            (_, RawAppPermission::Unsupported { .. }) => false,
            (Self::All {}, _) => true,
            (Self::Opaque { data: ranges }, RawAppPermission::Opaque { data, .. }) => {
                ranges.iter().any(|range| range == data)
            }
            (
                Self::Bitmap {
                    subordinate_may_have: value,
                    subordinate_must_have: mask,
                },
                RawAppPermission::Bitmap { data, .. },
            ) => {
                if value.len() != mask.len() || data.len() != mask.len() {
                    return false;
                }

                data.iter()
                    .zip(value)
                    .zip(mask)
                    .all(|((&ssp_byte, &value_byte), &mask_byte)| {
                        (ssp_byte & mask_byte) == (value_byte & mask_byte)
                    })
            }
            _ => false,
        }
    }
}

impl From<&rasn_its::ieee1609dot2::PsidGroupPermissions> for CertPermission {
    fn from(value: &rasn_its::ieee1609dot2::PsidGroupPermissions) -> Self {
        use num_traits::cast::ToPrimitive;

        let min_chain_length = value.min_chain_length.to_u64().unwrap();
        let chain_length_range = value.chain_length_range.to_u64().unwrap();
        Self {
            chain_length: ChainLength(min_chain_length..=min_chain_length + chain_length_range),
            end_entity_authorization: value.ee_type.0.data[0]
                & rasn_its::ieee1609dot2::EndEntityType::APP
                != 0,
            end_entity_enrollment: value.ee_type.0.data[0]
                & rasn_its::ieee1609dot2::EndEntityType::ENROLL
                != 0,
            subject_permissions: match &value.subject_permissions {
                rasn_its::ieee1609dot2::SubjectPermissions::All(()) => {
                    CertSubjectPermissions::All {}
                }
                rasn_its::ieee1609dot2::SubjectPermissions::Explicit(subject_perms) => {
                    CertSubjectPermissions::Explicit {
                        permissions: subject_perms.0.iter().map(Into::into).collect(),
                    }
                }
                _ => CertSubjectPermissions::Unknown {},
            },
        }
    }
}

impl From<&rasn_its::ieee1609dot2::base_types::PsidSspRange> for CertSubjectPermission {
    fn from(value: &rasn_its::ieee1609dot2::base_types::PsidSspRange) -> Self {
        Self {
            psid: (&value.psid).into(),
            auth: match &value.ssp_range {
                None | Some(rasn_its::ieee1609dot2::base_types::SspRange::All(())) => {
                    CertSubjectAuthorization::All {}
                }
                Some(rasn_its::ieee1609dot2::base_types::SspRange::Opaque(v)) => {
                    CertSubjectAuthorization::Opaque {
                        data: v.iter().map(|o| o.to_vec()).collect(),
                    }
                }
                Some(rasn_its::ieee1609dot2::base_types::SspRange::BitmapSspRange(v)) => {
                    CertSubjectAuthorization::Bitmap {
                        subordinate_may_have: v.ssp_value.to_vec(),
                        subordinate_must_have: v.ssp_bitmask.to_vec(),
                    }
                }
                Some(_) => CertSubjectAuthorization::Unsupported {},
            },
        }
    }
}
