#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_base_types {
    extern crate alloc;
    use rasn_its::ts103097::{
        EtsiTs103097Data, EtsiTs103097DataEncrypted, EtsiTs103097DataEncryptedUnicast,
        EtsiTs103097DataSigned, EtsiTs103097DataSignedAndEncryptedUnicast,
        EtsiTs103097DataSignedExternalPayload, EtsiTs103097DataUnsecured,
    };
    use rasn_its::ieee1609dot2::{
        CertificateId, HashedData, SequenceOfPsidGroupPermissions,
    };
    use rasn_its::ieee1609dot2::base_types::{
        GeographicRegion, SequenceOfPsidSsp, SubjectAssurance, ValidityPeriod,
        HashedId8, PublicEncryptionKey, PublicVerificationKey, Signature, Time32,
    };
    use alloc::boxed::Box;
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("1..=255"))]
    pub struct CertificateFormat(pub u8);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct CertificateSubjectAttributes {
        pub id: Option<CertificateId>,
        #[rasn(identifier = "validityPeriod")]
        pub validity_period: Option<ValidityPeriod>,
        pub region: Option<GeographicRegion>,
        #[rasn(identifier = "assuranceLevel")]
        pub assurance_level: Option<SubjectAssurance>,
        #[rasn(identifier = "appPermissions")]
        pub app_permissions: Option<SequenceOfPsidSsp>,
        #[rasn(identifier = "certIssuePermissions")]
        pub cert_issue_permissions: Option<SequenceOfPsidGroupPermissions>,
    }
    impl CertificateSubjectAttributes {
        pub fn new(
            id: Option<CertificateId>,
            validity_period: Option<ValidityPeriod>,
            region: Option<GeographicRegion>,
            assurance_level: Option<SubjectAssurance>,
            app_permissions: Option<SequenceOfPsidSsp>,
            cert_issue_permissions: Option<SequenceOfPsidGroupPermissions>,
        ) -> Self {
            Self {
                id,
                validity_period,
                region,
                assurance_level,
                app_permissions,
                cert_issue_permissions,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(choice, automatic_tags)]
    pub enum EcSignature {
        #[rasn(value("0.."))]
        encryptedEcSignature(EtsiTs103097DataEncrypted<EtsiTs103097DataSignedExternalPayload<()>>),
        ecSignature(EtsiTs103097DataSignedExternalPayload<()>),
    }
    impl From<EtsiTs103097DataEncrypted<EtsiTs103097DataSignedExternalPayload<()>>> for EcSignature {
        fn from(value: EtsiTs103097DataEncrypted<EtsiTs103097DataSignedExternalPayload<()>>) -> Self {
            Self::encryptedEcSignature(value)
        }
    }
    impl From<EtsiTs103097DataSignedExternalPayload<()>> for EcSignature {
        fn from(value: EtsiTs103097DataSignedExternalPayload<()>) -> Self {
            Self::ecSignature(value)
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct PublicKeys {
        #[rasn(identifier = "verificationKey")]
        pub verification_key: PublicVerificationKey,
        #[rasn(identifier = "encryptionKey")]
        pub encryption_key: Option<PublicEncryptionKey>,
    }
    impl PublicKeys {
        pub fn new(
            verification_key: PublicVerificationKey,
            encryption_key: Option<PublicEncryptionKey>,
        ) -> Self {
            Self {
                verification_key,
                encryption_key,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Version(pub Integer);
}

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts_102941_messages_ca {
    use rasn::prelude::*;
    use rasn_its::ts103097::EtsiTs103097DataSigned;
    use super::etsi_ts102941_base_types::Version;
    use super::etsi_ts102941_types_enrolment::{InnerEcRequestSignedForPop, InnerEcResponse};
    use super::etsi_ts102941_types_authorization::{InnerAtRequest, InnerAtResponse};
    use super::etsi_ts102941_trust_lists::{ToBeSignedCrl, ToBeSignedTlmCtl, ToBeSignedRcaCtl};
    use super::etsi_ts102941_types_authorization_validation::{AuthorizationValidationRequest, AuthorizationValidationResponse};
    use super::etsi_ts102941_types_ca_management::CaCertificateRequest;
    use super::etsi_ts102941_types_link_certificate::{ToBeSignedLinkCertificateTlm, ToBeSignedLinkCertificateRca};

    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(automatic_tags)]
    pub struct EtsiTs102941Data {
        #[rasn(value("1"))]
        pub version: Version,
        pub content: EtsiTs102941DataContent,
    }

    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum EtsiTs102941DataContent {
        enrolmentRequest(InnerEcRequestSignedForPop),
        enrolmentResponse(InnerEcResponse),
        authorizationRequest(InnerAtRequest),
        authorizationResponse(InnerAtResponse),
        certificateRevocationList(ToBeSignedCrl),
        certificateTrustListTlm(ToBeSignedTlmCtl),
        certificateTrustListRca(ToBeSignedRcaCtl),
        authorizationValidationRequest(AuthorizationValidationRequest),
        authorizationValidationResponse(AuthorizationValidationResponse),
        caCertificateRequest(CaCertificateRequest),
        #[rasn(extension_addition)]
        linkCertificateTlm(ToBeSignedLinkCertificateTlm),
        #[rasn(extension_addition)]
        singleSignedLinkCertificateRca(ToBeSignedLinkCertificateRca),
        #[rasn(extension_addition)]
        doubleSignedlinkCertificateRca(RcaSingleSignedLinkCertificateMessage),
    }
    impl From<InnerEcRequestSignedForPop> for EtsiTs102941DataContent {
        fn from(value: InnerEcRequestSignedForPop) -> Self {
            Self::enrolmentRequest(value)
        }
    }
    impl From<InnerEcResponse> for EtsiTs102941DataContent {
        fn from(value: InnerEcResponse) -> Self {
            Self::enrolmentResponse(value)
        }
    }
    impl From<InnerAtRequest> for EtsiTs102941DataContent {
        fn from(value: InnerAtRequest) -> Self {
            Self::authorizationRequest(value)
        }
    }
    impl From<InnerAtResponse> for EtsiTs102941DataContent {
        fn from(value: InnerAtResponse) -> Self {
            Self::authorizationResponse(value)
        }
    }
    impl From<ToBeSignedCrl> for EtsiTs102941DataContent {
        fn from(value: ToBeSignedCrl) -> Self {
            Self::certificateRevocationList(value)
        }
    }
    impl From<ToBeSignedTlmCtl> for EtsiTs102941DataContent {
        fn from(value: ToBeSignedTlmCtl) -> Self {
            Self::certificateTrustListTlm(value)
        }
    }
    impl From<ToBeSignedRcaCtl> for EtsiTs102941DataContent {
        fn from(value: ToBeSignedRcaCtl) -> Self {
            Self::certificateTrustListRca(value)
        }
    }
    impl From<AuthorizationValidationRequest> for EtsiTs102941DataContent {
        fn from(value: AuthorizationValidationRequest) -> Self {
            Self::authorizationValidationRequest(value)
        }
    }
    impl From<AuthorizationValidationResponse> for EtsiTs102941DataContent {
        fn from(value: AuthorizationValidationResponse) -> Self {
            Self::authorizationValidationResponse(value)
        }
    }
    impl From<CaCertificateRequest> for EtsiTs102941DataContent {
        fn from(value: CaCertificateRequest) -> Self {
            Self::caCertificateRequest(value)
        }
    }
    impl From<ToBeSignedLinkCertificateTlm> for EtsiTs102941DataContent {
        fn from(value: ToBeSignedLinkCertificateTlm) -> Self {
            Self::linkCertificateTlm(value)
        }
    }
    impl From<ToBeSignedLinkCertificateRca> for EtsiTs102941DataContent {
        fn from(value: ToBeSignedLinkCertificateRca) -> Self {
            Self::singleSignedLinkCertificateRca(value)
        }
    }
    impl From<RcaSingleSignedLinkCertificateMessage> for EtsiTs102941DataContent {
        fn from(value: RcaSingleSignedLinkCertificateMessage) -> Self {
            Self::doubleSignedlinkCertificateRca(value)
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(delegate)]
    pub struct RcaCertificateTrustListMessage(pub EtsiTs103097DataSigned<EtsiTs102941Data>);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(delegate)]
    pub struct RcaDoubleSignedLinkCertificateMessage(pub EtsiTs103097DataSigned<EtsiTs102941Data>);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(delegate)]
    pub struct RcaSingleSignedLinkCertificateMessage(pub EtsiTs103097DataSigned<EtsiTs102941Data>);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(delegate)]
    pub struct TlmCertificateTrustListMessage(pub EtsiTs103097DataSigned<EtsiTs102941Data>);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(delegate)]
    pub struct TlmLinkCertificateMessage(pub EtsiTs103097DataSigned<EtsiTs102941Data>);
}

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_types_enrolment {
    extern crate alloc;
    use super::etsi_ts102941_base_types::{
        CertificateFormat, CertificateSubjectAttributes, EcSignature, PublicKeys,
        Version,
    };
    use rasn_its::ieee1609dot2::base_types::HashedId8;
    use rasn_its::ts103097::{EtsiTs103097Certificate, EtsiTs103097DataSigned};
    use alloc::boxed::Box;
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash, Copy)]
    #[rasn(enumerated)]
    #[non_exhaustive]
    pub enum EnrolmentResponseCode {
        ok = 0,
        cantparse = 1,
        badcontenttype = 2,
        imnottherecipient = 3,
        unknownencryptionalgorithm = 4,
        decryptionfailed = 5,
        unknownits = 6,
        invalidsignature = 7,
        invalidencryptionkey = 8,
        baditsstatus = 9,
        incompleterequest = 10,
        deniedpermissions = 11,
        invalidkeys = 12,
        deniedrequest = 13,
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct InnerEcRequest {
        #[rasn(identifier = "itsId")]
        pub its_id: OctetString,
        #[rasn(identifier = "certificateFormat")]
        pub certificate_format: CertificateFormat,
        #[rasn(identifier = "publicKeys")]
        pub public_keys: PublicKeys,
        #[rasn(value("0.."), identifier = "requestedSubjectAttributes")]
        pub requested_subject_attributes: CertificateSubjectAttributes,
    }
    impl InnerEcRequest {
        pub fn new(
            its_id: OctetString,
            certificate_format: CertificateFormat,
            public_keys: PublicKeys,
            requested_subject_attributes: CertificateSubjectAttributes,
        ) -> Self {
            Self {
                its_id,
                certificate_format,
                public_keys,
                requested_subject_attributes,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(delegate)]
    pub struct InnerEcRequestSignedForPop(pub EtsiTs103097DataSigned<InnerEcRequest>);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct InnerEcResponse {
        #[rasn(size("16"), identifier = "requestHash")]
        pub request_hash: OctetString,
        #[rasn(identifier = "responseCode")]
        pub response_code: EnrolmentResponseCode,
        pub certificate: Option<EtsiTs103097Certificate>,
    }
    impl InnerEcResponse {
        pub fn new(
            request_hash: OctetString,
            response_code: EnrolmentResponseCode,
            certificate: Option<EtsiTs103097Certificate>,
        ) -> Self {
            Self {
                request_hash,
                response_code,
                certificate,
            }
        }
    }
}

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_types_authorization {
    extern crate alloc;
    use super::etsi_ts102941_base_types::{
        CertificateFormat, CertificateSubjectAttributes, EcSignature, PublicKeys,
        Version,
    };
    use rasn_its::ieee1609dot2::base_types::HashedId8;
    use rasn_its::ts103097::{EtsiTs103097Certificate, EtsiTs103097DataSigned};
    use alloc::boxed::Box;
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash, Copy)]
    #[rasn(enumerated)]
    #[non_exhaustive]
    pub enum AuthorizationResponseCode {
        ok = 0,
        #[rasn(identifier = "its-aa-cantparse")]
        its_aa_cantparse = 1,
        #[rasn(identifier = "its-aa-badcontenttype")]
        its_aa_badcontenttype = 2,
        #[rasn(identifier = "its-aa-imnottherecipient")]
        its_aa_imnottherecipient = 3,
        #[rasn(identifier = "its-aa-unknownencryptionalgorithm")]
        its_aa_unknownencryptionalgorithm = 4,
        #[rasn(identifier = "its-aa-decryptionfailed")]
        its_aa_decryptionfailed = 5,
        #[rasn(identifier = "its-aa-keysdontmatch")]
        its_aa_keysdontmatch = 6,
        #[rasn(identifier = "its-aa-incompleterequest")]
        its_aa_incompleterequest = 7,
        #[rasn(identifier = "its-aa-invalidencryptionkey")]
        its_aa_invalidencryptionkey = 8,
        #[rasn(identifier = "its-aa-outofsyncrequest")]
        its_aa_outofsyncrequest = 9,
        #[rasn(identifier = "its-aa-unknownea")]
        its_aa_unknownea = 10,
        #[rasn(identifier = "its-aa-invalidea")]
        its_aa_invalidea = 11,
        #[rasn(identifier = "its-aa-deniedpermissions")]
        its_aa_deniedpermissions = 12,
        #[rasn(identifier = "aa-ea-cantreachea")]
        aa_ea_cantreachea = 13,
        #[rasn(identifier = "ea-aa-cantparse")]
        ea_aa_cantparse = 14,
        #[rasn(identifier = "ea-aa-badcontenttype")]
        ea_aa_badcontenttype = 15,
        #[rasn(identifier = "ea-aa-imnottherecipient")]
        ea_aa_imnottherecipient = 16,
        #[rasn(identifier = "ea-aa-unknownencryptionalgorithm")]
        ea_aa_unknownencryptionalgorithm = 17,
        #[rasn(identifier = "ea-aa-decryptionfailed")]
        ea_aa_decryptionfailed = 18,
        invalidaa = 19,
        invalidaasignature = 20,
        wrongea = 21,
        unknownits = 22,
        invalidsignature = 23,
        invalidencryptionkey = 24,
        deniedpermissions = 25,
        deniedtoomanycerts = 26,
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct InnerAtRequest {
        #[rasn(identifier = "publicKeys")]
        pub public_keys: PublicKeys,
        #[rasn(size("32"), identifier = "hmacKey")]
        pub hmac_key: OctetString,
        #[rasn(identifier = "sharedAtRequest")]
        pub shared_at_request: SharedAtRequest,
        #[rasn(identifier = "ecSignature")]
        pub ec_signature: EcSignature,
    }
    impl InnerAtRequest {
        pub fn new(
            public_keys: PublicKeys,
            hmac_key: OctetString,
            shared_at_request: SharedAtRequest,
            ec_signature: EcSignature,
        ) -> Self {
            Self {
                public_keys,
                hmac_key,
                shared_at_request,
                ec_signature,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct InnerAtResponse {
        #[rasn(size("16"), identifier = "requestHash")]
        pub request_hash: OctetString,
        #[rasn(identifier = "responseCode")]
        pub response_code: AuthorizationResponseCode,
        pub certificate: Option<EtsiTs103097Certificate>,
    }
    impl InnerAtResponse {
        pub fn new(
            request_hash: OctetString,
            response_code: AuthorizationResponseCode,
            certificate: Option<EtsiTs103097Certificate>,
        ) -> Self {
            Self {
                request_hash,
                response_code,
                certificate,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct SharedAtRequest {
        #[rasn(identifier = "eaId")]
        pub ea_id: HashedId8,
        #[rasn(size("16"), identifier = "keyTag")]
        pub key_tag: OctetString,
        #[rasn(identifier = "certificateFormat")]
        pub certificate_format: CertificateFormat,
        #[rasn(value("0.."), identifier = "requestedSubjectAttributes")]
        pub requested_subject_attributes: CertificateSubjectAttributes,
    }
    impl SharedAtRequest {
        pub fn new(
            ea_id: HashedId8,
            key_tag: OctetString,
            certificate_format: CertificateFormat,
            requested_subject_attributes: CertificateSubjectAttributes,
        ) -> Self {
            Self {
                ea_id,
                key_tag,
                certificate_format,
                requested_subject_attributes,
            }
        }
    }
}

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_trust_lists {
    extern crate alloc;
    use super::etsi_ts102941_base_types::Version;
    use rasn_its::ieee1609dot2::base_types::{HashedId8, Time32};
    use rasn_its::ts103097::{
        EtsiTs103097Certificate, EtsiTs103097DataSigned, EtsiTs103097DataSignedAndEncrypted,
    };
    use alloc::boxed::Box;
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(automatic_tags)]
    pub struct AaEntry {
        #[rasn(identifier = "aaCertificate")]
        pub aa_certificate: EtsiTs103097Certificate,
        #[rasn(identifier = "accessPoint")]
        pub access_point: Url,
    }
    impl AaEntry {
        pub fn new(aa_certificate: EtsiTs103097Certificate, access_point: Url) -> Self {
            Self {
                aa_certificate,
                access_point,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct CrlEntry(pub HashedId8);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum CtlCommand {
        add(CtlEntry),
        delete(CtlDelete),
    }
    impl From<CtlEntry> for CtlCommand {
        fn from(value: CtlEntry) -> Self {
            Self::add(value)
        }
    }
    impl From<CtlDelete> for CtlCommand {
        fn from(value: CtlDelete) -> Self {
            Self::delete(value)
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum CtlDelete {
        cert(HashedId8),
        dc(DcDelete),
    }
    impl From<HashedId8> for CtlDelete {
        fn from(value: HashedId8) -> Self {
            Self::cert(value)
        }
    }
    impl From<DcDelete> for CtlDelete {
        fn from(value: DcDelete) -> Self {
            Self::dc(value)
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(choice, automatic_tags)]
    #[non_exhaustive]
    pub enum CtlEntry {
        rca(RootCaEntry),
        ea(EaEntry),
        aa(AaEntry),
        dc(DcEntry),
        tlm(TlmEntry),
    }
    impl From<RootCaEntry> for CtlEntry {
        fn from(value: RootCaEntry) -> Self {
            Self::rca(value)
        }
    }
    impl From<EaEntry> for CtlEntry {
        fn from(value: EaEntry) -> Self {
            Self::ea(value)
        }
    }
    impl From<AaEntry> for CtlEntry {
        fn from(value: AaEntry) -> Self {
            Self::aa(value)
        }
    }
    impl From<DcEntry> for CtlEntry {
        fn from(value: DcEntry) -> Self {
            Self::dc(value)
        }
    }
    impl From<TlmEntry> for CtlEntry {
        fn from(value: TlmEntry) -> Self {
            Self::tlm(value)
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct CtlFormat {
        pub version: Version,
        #[rasn(identifier = "nextUpdate")]
        pub next_update: Time32,
        #[rasn(identifier = "isFullCtl")]
        pub is_full_ctl: bool,
        #[rasn(value("0..=255"), identifier = "ctlSequence")]
        pub ctl_sequence: u8,
        #[rasn(identifier = "ctlCommands")]
        pub ctl_commands: SequenceOf<CtlCommand>,
    }
    impl CtlFormat {
        pub fn new(
            version: Version,
            next_update: Time32,
            is_full_ctl: bool,
            ctl_sequence: u8,
            ctl_commands: SequenceOf<CtlCommand>,
        ) -> Self {
            Self {
                version,
                next_update,
                is_full_ctl,
                ctl_sequence,
                ctl_commands,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct DcDelete(pub Url);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    pub struct DcEntry {
        pub url: Url,
        pub cert: SequenceOf<HashedId8>,
    }
    impl DcEntry {
        pub fn new(url: Url, cert: SequenceOf<HashedId8>) -> Self {
            Self { url, cert }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(delegate)]
    pub struct DeltaCtl(pub CtlFormat);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(automatic_tags)]
    pub struct EaEntry {
        #[rasn(identifier = "eaCertificate")]
        pub ea_certificate: EtsiTs103097Certificate,
        #[rasn(identifier = "aaAccessPoint")]
        pub aa_access_point: Url,
        #[rasn(identifier = "itsAccessPoint")]
        pub its_access_point: Option<Url>,
    }
    impl EaEntry {
        pub fn new(
            ea_certificate: EtsiTs103097Certificate,
            aa_access_point: Url,
            its_access_point: Option<Url>,
        ) -> Self {
            Self {
                ea_certificate,
                aa_access_point,
                its_access_point,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(delegate)]
    pub struct FullCtl(pub CtlFormat);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(automatic_tags)]
    pub struct RootCaEntry {
        #[rasn(identifier = "selfsignedRootCa")]
        pub selfsigned_root_ca: EtsiTs103097Certificate,
        #[rasn(identifier = "successorTo")]
        pub successor_to: Option<EtsiTs103097Certificate>,
    }
    impl RootCaEntry {
        pub fn new(
            selfsigned_root_ca: EtsiTs103097Certificate,
            successor_to: Option<EtsiTs103097Certificate>,
        ) -> Self {
            Self {
                selfsigned_root_ca,
                successor_to,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(automatic_tags)]
    pub struct TlmEntry {
        #[rasn(identifier = "selfSignedTLMCertificate")]
        pub self_signed_tlmcertificate: EtsiTs103097Certificate,
        #[rasn(identifier = "successorTo")]
        pub successor_to: Option<EtsiTs103097Certificate>,
        #[rasn(identifier = "accessPoint")]
        pub access_point: Url,
    }
    impl TlmEntry {
        pub fn new(
            self_signed_tlmcertificate: EtsiTs103097Certificate,
            successor_to: Option<EtsiTs103097Certificate>,
            access_point: Url,
        ) -> Self {
            Self {
                self_signed_tlmcertificate,
                successor_to,
                access_point,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct ToBeSignedCrl {
        pub version: Version,
        #[rasn(identifier = "thisUpdate")]
        pub this_update: Time32,
        #[rasn(identifier = "nextUpdate")]
        pub next_update: Time32,
        pub entries: SequenceOf<CrlEntry>,
    }
    impl ToBeSignedCrl {
        pub fn new(
            version: Version,
            this_update: Time32,
            next_update: Time32,
            entries: SequenceOf<CrlEntry>,
        ) -> Self {
            Self {
                version,
                this_update,
                next_update,
                entries,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(delegate)]
    pub struct ToBeSignedRcaCtl(pub CtlFormat);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(delegate)]
    pub struct ToBeSignedTlmCtl(pub CtlFormat);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Url(pub Ia5String);
}

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_types_authorization_validation {
    extern crate alloc;
    use super::etsi_ts102941_base_types::{
        CertificateFormat, CertificateSubjectAttributes, EcSignature, PublicKeys, Version,
    };
    use rasn_its::ieee1609dot2::base_types::HashedId8;
    use super::etsi_ts102941_types_authorization::SharedAtRequest;
    use rasn_its::ts103097::EtsiTs103097Certificate;
    use alloc::boxed::Box;
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct AuthorizationValidationRequest {
        #[rasn(identifier = "sharedAtRequest")]
        pub shared_at_request: SharedAtRequest,
        #[rasn(identifier = "ecSignature")]
        pub ec_signature: EcSignature,
    }
    impl AuthorizationValidationRequest {
        pub fn new(shared_at_request: SharedAtRequest, ec_signature: EcSignature) -> Self {
            Self {
                shared_at_request,
                ec_signature,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct AuthorizationValidationResponse {
        #[rasn(size("16"), identifier = "requestHash")]
        pub request_hash: OctetString,
        #[rasn(identifier = "responseCode")]
        pub response_code: AuthorizationValidationResponseCode,
        #[rasn(value("0.."), identifier = "confirmedSubjectAttributes")]
        pub confirmed_subject_attributes: Option<CertificateSubjectAttributes>,
    }
    impl AuthorizationValidationResponse {
        pub fn new(
            request_hash: OctetString,
            response_code: AuthorizationValidationResponseCode,
            confirmed_subject_attributes: Option<CertificateSubjectAttributes>,
        ) -> Self {
            Self {
                request_hash,
                response_code,
                confirmed_subject_attributes,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash, Copy)]
    #[rasn(enumerated)]
    #[non_exhaustive]
    pub enum AuthorizationValidationResponseCode {
        ok = 0,
        cantparse = 1,
        badcontenttype = 2,
        imnottherecipient = 3,
        unknownencryptionalgorithm = 4,
        decryptionfailed = 5,
        invalidaa = 6,
        invalidaasignature = 7,
        wrongea = 8,
        unknownits = 9,
        invalidsignature = 10,
        invalidencryptionkey = 11,
        deniedpermissions = 12,
        deniedtoomanycerts = 13,
        deniedrequest = 14,
    }
}

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_types_ca_management {
    extern crate alloc;
    use super::etsi_ts102941_base_types::{CertificateSubjectAttributes, PublicKeys};
    use rasn_its::ts103097::{EtsiTs103097Certificate, EtsiTs103097DataSigned};
    use alloc::boxed::Box;
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct CaCertificateRequest {
        #[rasn(identifier = "publicKeys")]
        pub public_keys: PublicKeys,
        #[rasn(identifier = "requestedSubjectAttributes")]
        pub requested_subject_attributes: CertificateSubjectAttributes,
    }
    impl CaCertificateRequest {
        pub fn new(
            public_keys: PublicKeys,
            requested_subject_attributes: CertificateSubjectAttributes,
        ) -> Self {
            Self {
                public_keys,
                requested_subject_attributes,
            }
        }
    }
}

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod etsi_ts102941_types_link_certificate {
    extern crate alloc;
    use rasn_its::ieee1609dot2::HashedData;
    use rasn_its::ieee1609dot2::base_types::Time32;
    use alloc::boxed::Box;
    use core::borrow::Borrow;
    use lazy_static::lazy_static;
    use rasn::prelude::*;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(automatic_tags)]
    #[non_exhaustive]
    pub struct ToBeSignedLinkCertificate {
        #[rasn(identifier = "expiryTime")]
        pub expiry_time: Time32,
        #[rasn(identifier = "certificateHash")]
        pub certificate_hash: HashedData,
    }
    impl ToBeSignedLinkCertificate {
        pub fn new(expiry_time: Time32, certificate_hash: HashedData) -> Self {
            Self {
                expiry_time,
                certificate_hash,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct ToBeSignedLinkCertificateRca(pub ToBeSignedLinkCertificate);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct ToBeSignedLinkCertificateTlm(pub ToBeSignedLinkCertificate);
}

