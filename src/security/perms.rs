use crate::security::certs::{PSID_CAM, PSID_CERT_REQ, PSID_CP, PSID_CRL, PSID_CTL, PSID_DENM, PSID_GN_MGMT, PSID_IVIM, PSID_MR, PSID_POI, PSID_RLT, PSID_SA, PSID_TLC_REQ, PSID_TLC_STATUS, PSID_TLM, PSID_VRU};

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub enum ProviderService {
    CAM,
    DENM,
    TLM,
    RLT,
    IVIM,
    CTL,
    TLCReq,
    TLCStat,
    GnMgmt,
    CRL,
    CertReq,
    VRU,
    CP,
    MR,
    POI,
    SA,
    Other(u64),
}

impl serde::Serialize for ProviderService {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            ProviderService::CAM => serializer.serialize_str("cam"),
            ProviderService::DENM => serializer.serialize_str("denm"),
            ProviderService::TLM => serializer.serialize_str("ctl"),
            ProviderService::RLT => serializer.serialize_str("rlt"),
            ProviderService::IVIM => serializer.serialize_str("ivim"),
            ProviderService::CTL => serializer.serialize_str("ctl"),
            ProviderService::TLCReq => serializer.serialize_str("tlc_req"),
            ProviderService::TLCStat => serializer.serialize_str("tlc_stat"),
            ProviderService::GnMgmt => serializer.serialize_str("gm_mgmt"),
            ProviderService::CRL => serializer.serialize_str("crl"),
            ProviderService::CertReq => serializer.serialize_str("cert_req"),
            ProviderService::VRU => serializer.serialize_str("vru"),
            ProviderService::CP => serializer.serialize_str("cp"),
            ProviderService::MR => serializer.serialize_str("mr"),
            ProviderService::POI => serializer.serialize_str("poi"),
            ProviderService::SA => serializer.serialize_str("sa"),
            ProviderService::Other(v) => serializer.serialize_u64(*v),
        }
    }
}

impl From<&rasn_its::ieee1609dot2::base_types::Psid> for ProviderService {
    fn from(value: &rasn_its::ieee1609dot2::base_types::Psid) -> Self {
        use num_traits::cast::ToPrimitive;

        if value.0 == *PSID_CAM {
            ProviderService::CAM
        } else if value.0 == *PSID_DENM {
            ProviderService::DENM
        } else if value.0 == *PSID_TLM {
            ProviderService::TLM
        } else if value.0 == *PSID_RLT {
            ProviderService::RLT
        } else if value.0 == *PSID_IVIM {
            ProviderService::IVIM
        } else if value.0 == *PSID_CTL {
            ProviderService::CTL
        } else if value.0 == *PSID_TLC_REQ {
            ProviderService::TLCReq
        } else if value.0 == *PSID_TLC_STATUS {
            ProviderService::TLCStat
        } else if value.0 == *PSID_GN_MGMT {
            ProviderService::GnMgmt
        } else if value.0 == *PSID_CRL {
            ProviderService::CRL
        } else if value.0 == *PSID_CERT_REQ {
            ProviderService::CertReq
        } else if value.0 == *PSID_VRU {
            ProviderService::VRU
        } else if value.0 == *PSID_CP {
            ProviderService::CP
        } else if value.0 == *PSID_MR {
            ProviderService::MR
        } else if value.0 == *PSID_POI {
            ProviderService::POI
        } else if value.0 == *PSID_SA {
            ProviderService::SA
        } else {
            ProviderService::Other(value.0.to_u64().unwrap_or_default())
        }
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Default, Clone, PartialOrd, Ord)]
pub struct CAMPermissions {
    pub cen_dsrc_tolling_zone: bool,
    pub public_transport: bool,
    pub special_transport: bool,
    pub dangerous_goods: bool,
    pub roadworks: bool,
    pub rescue: bool,
    pub emergency: bool,
    pub safety_car: bool,
    pub closed_lanes: bool,
    pub request_right_of_way: bool,
    pub request_free_crossing: bool,
    pub no_passing: bool,
    pub no_passing_for_trucks: bool,
    pub speed_limit: bool,
    #[serde(skip_serializing)]
    _orig_value: alloc::vec::Vec<u8>,
}

impl CAMPermissions {
    fn from_bitmap_v1(ssp: &rasn_its::ieee1609dot2::base_types::BitmapSsp) -> Self {
        Self {
            cen_dsrc_tolling_zone: ssp[1] & 0x80 != 0,
            public_transport: ssp[1] & 0x40 != 0,
            special_transport: ssp[1] & 0x20 != 0,
            dangerous_goods: ssp[1] & 0x10 != 0,
            roadworks: ssp[1] & 0x08 != 0,
            rescue: ssp[1] & 0x04 != 0,
            emergency: ssp[1] & 0x02 != 0,
            safety_car: ssp[1] & 0x01 != 0,
            closed_lanes: ssp[2] & 0x80 != 0,
            request_right_of_way: ssp[2] & 0x40 != 0,
            request_free_crossing: ssp[2] & 0x20 != 0,
            no_passing: ssp[2] & 0x10 != 0,
            no_passing_for_trucks: ssp[2] & 0x08 != 0,
            speed_limit: ssp[2] & 0x04 != 0,
            _orig_value: ssp.0.to_vec(),
        }
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct DENMPermissions {
    pub traffic_condition: bool,
    pub accident: bool,
    pub roadworks: bool,
    pub adverse_weather_condition_adhesion: bool,
    pub hazardous_location_surface_condition: bool,
    pub hazardous_location_obstacle_on_the_road: bool,
    pub hazardous_location_animal_on_the_road: bool,
    pub human_presence_on_the_road: bool,
    pub wrong_way_driving: bool,
    pub rescue_and_recovery_work_in_progress: bool,
    pub adverse_weather_condition_extreme_weather_condition: bool,
    pub adverse_weather_condition_visibility: bool,
    pub adverse_weather_condition_precipitation: bool,
    pub slow_vehicle: bool,
    pub dangerous_end_of_queue: bool,
    pub vehicle_breakdown: bool,
    pub post_crash: bool,
    pub human_problem: bool,
    pub stationary_vehicle: bool,
    pub emergency_vehicle_approaching: bool,
    pub hazardous_location_dangerous_curve: bool,
    pub collision_risk: bool,
    pub signal_violation: bool,
    pub dangerous_situation: bool,
    pub impassability: bool,
    pub aquaplaning: bool,
    pub public_transport_vehicle_approaching: bool,
    pub railway_level_crossing: bool,
    #[serde(skip_serializing)]
    _orig_value: alloc::vec::Vec<u8>,
}

impl DENMPermissions {
    fn from_bitmap_v1(ssp: &rasn_its::ieee1609dot2::base_types::BitmapSsp) -> Self {
        Self {
            traffic_condition: ssp[1] & 0x80 != 0,
            accident: ssp[1] & 0x40 != 0,
            roadworks: ssp[1] & 0x20 != 0,
            adverse_weather_condition_adhesion: ssp[1] & 0x10 != 0,
            hazardous_location_surface_condition: ssp[1] & 0x08 != 0,
            hazardous_location_obstacle_on_the_road: ssp[1] & 0x04 != 0,
            hazardous_location_animal_on_the_road: ssp[1] & 0x02 != 0,
            human_presence_on_the_road: ssp[1] & 0x01 != 0,
            wrong_way_driving: ssp[2] & 0x80 != 0,
            rescue_and_recovery_work_in_progress: ssp[2] & 0x40 != 0,
            adverse_weather_condition_extreme_weather_condition: ssp[2] & 0x20 != 0,
            adverse_weather_condition_visibility: ssp[2] & 0x10 != 0,
            adverse_weather_condition_precipitation: ssp[2] & 0x08 != 0,
            slow_vehicle: ssp[2] & 0x04 != 0,
            dangerous_end_of_queue: ssp[2] & 0x02 != 0,
            vehicle_breakdown: ssp[2] & 0x01 != 0,
            post_crash: ssp[3] & 0x80 != 0,
            human_problem: ssp[3] & 0x40 != 0,
            stationary_vehicle: ssp[3] & 0x20 != 0,
            emergency_vehicle_approaching: ssp[3] & 0x10 != 0,
            hazardous_location_dangerous_curve: ssp[3] & 0x08 != 0,
            collision_risk: ssp[3] & 0x04 != 0,
            signal_violation: ssp[3] & 0x02 != 0,
            dangerous_situation: ssp[3] & 0x01 != 0,
            impassability: false,
            aquaplaning: false,
            public_transport_vehicle_approaching: false,
            railway_level_crossing: false,
            _orig_value: ssp.0.to_vec(),
        }
    }

    fn from_bitmap_v2(ssp: &rasn_its::ieee1609dot2::base_types::BitmapSsp) -> Self {
        Self {
            traffic_condition: ssp[1] & 0x80 != 0,
            accident: ssp[1] & 0x40 != 0,
            roadworks: ssp[1] & 0x20 != 0,
            adverse_weather_condition_adhesion: ssp[1] & 0x10 != 0,
            hazardous_location_surface_condition: ssp[1] & 0x08 != 0,
            hazardous_location_obstacle_on_the_road: ssp[1] & 0x04 != 0,
            hazardous_location_animal_on_the_road: ssp[1] & 0x02 != 0,
            human_presence_on_the_road: ssp[1] & 0x01 != 0,
            wrong_way_driving: ssp[2] & 0x80 != 0,
            rescue_and_recovery_work_in_progress: ssp[2] & 0x40 != 0,
            adverse_weather_condition_extreme_weather_condition: ssp[2] & 0x20 != 0,
            adverse_weather_condition_visibility: ssp[2] & 0x10 != 0,
            adverse_weather_condition_precipitation: ssp[2] & 0x08 != 0,
            slow_vehicle: ssp[2] & 0x04 != 0,
            dangerous_end_of_queue: ssp[2] & 0x02 != 0,
            vehicle_breakdown: ssp[2] & 0x01 != 0,
            post_crash: ssp[3] & 0x80 != 0,
            human_problem: ssp[3] & 0x40 != 0,
            stationary_vehicle: ssp[3] & 0x20 != 0,
            emergency_vehicle_approaching: ssp[3] & 0x10 != 0,
            hazardous_location_dangerous_curve: ssp[3] & 0x08 != 0,
            collision_risk: ssp[3] & 0x04 != 0,
            signal_violation: ssp[3] & 0x02 != 0,
            dangerous_situation: ssp[3] & 0x01 != 0,
            impassability: ssp[4] & 0x80 != 0,
            aquaplaning: ssp[4] & 0x40 != 0,
            public_transport_vehicle_approaching: ssp[4] & 0x20 != 0,
            railway_level_crossing: ssp[4] & 0x10 != 0,
            _orig_value: ssp.0.to_vec(),
        }
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct TLMPermissions {
    #[serde(skip_serializing)]
    _orig_value: alloc::vec::Vec<u8>,
}

impl TLMPermissions {
    fn from_bitmap_v1(ssp: &rasn_its::ieee1609dot2::base_types::BitmapSsp) -> Self {
        Self {
            _orig_value: ssp.0.to_vec(),
        }
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct RLTPermissions {
    #[serde(skip_serializing)]
    _orig_value: alloc::vec::Vec<u8>,
}

impl RLTPermissions {
    fn from_bitmap_v1(ssp: &rasn_its::ieee1609dot2::base_types::BitmapSsp) -> Self {
        Self {
            _orig_value: ssp.0.to_vec(),
        }
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct IVIMPermissions {
    #[serde(skip_serializing)]
    _orig_value: alloc::vec::Vec<u8>,
}

impl IVIMPermissions {
    fn from_bitmap_v1(ssp: &rasn_its::ieee1609dot2::base_types::BitmapSsp) -> Self {
        Self {
            _orig_value: ssp.0.to_vec(),
        }
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct TlcReqPermissions {
    #[serde(skip_serializing)]
    _orig_value: alloc::vec::Vec<u8>,
}

impl TlcReqPermissions {
    fn from_bitmap_v2(ssp: &rasn_its::ieee1609dot2::base_types::BitmapSsp) -> Self {
        Self {
            _orig_value: ssp.0.to_vec(),
        }
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct TlcStatusPermissions {
    #[serde(skip_serializing)]
    _orig_value: alloc::vec::Vec<u8>,
}

impl TlcStatusPermissions {
    fn from_bitmap_v1(ssp: &rasn_its::ieee1609dot2::base_types::BitmapSsp) -> Self {
        Self {
            _orig_value: ssp.0.to_vec(),
        }
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct CertificateRevocationListPermissions {
    #[serde(skip_serializing)]
    _orig_value: alloc::vec::Vec<u8>,
}

impl CertificateRevocationListPermissions {
    fn from_bitmap_v1(ssp: &rasn_its::ieee1609dot2::base_types::BitmapSsp) -> Self {
        Self {
            _orig_value: ssp.0.to_vec(),
        }
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct CertificateTrustListPermissions {
    pub tlm: bool,
    pub root_ca: bool,
    pub enrollment_authority: bool,
    pub authorization_authority: bool,
    pub distribution_centre: bool,
    #[serde(skip_serializing)]
    _orig_value: alloc::vec::Vec<u8>,
}

impl CertificateTrustListPermissions {
    fn from_bitmap_v1(ssp: &rasn_its::ieee1609dot2::base_types::BitmapSsp) -> Self {
        Self {
            tlm: ssp[1] & 0x80 != 0,
            root_ca: ssp[1] & 0x40 != 0,
            enrollment_authority: ssp[1] & 0x20 != 0,
            authorization_authority: ssp[1] & 0x10 != 0,
            distribution_centre: ssp[1] & 0x08 != 0,
            _orig_value: ssp.0.to_vec(),
        }
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Clone, PartialOrd, Ord)]
#[serde(tag = "type")]
pub enum AppPermission {
    #[serde(rename = "cam")]
    CAM(CAMPermissions),
    #[serde(rename = "denm")]
    DENM(DENMPermissions),
    #[serde(rename = "tlm")]
    TLM(TLMPermissions),
    #[serde(rename = "rlt")]
    RLT(RLTPermissions),
    #[serde(rename = "ivim")]
    IVIM(IVIMPermissions),
    #[serde(rename = "tlc_req")]
    TlcReq(TlcReqPermissions),
    #[serde(rename = "tlc_status")]
    TlcStatus(TlcStatusPermissions),
    #[serde(rename = "certificate_revocation_list")]
    CertificateRevocationList(CertificateRevocationListPermissions),
    #[serde(rename = "certificate_trust_list")]
    CertificateTrustList(CertificateTrustListPermissions),
    #[serde(rename = "unknown_bitmap")]
    UnknownBitmap {
        psid: ProviderService,
        #[serde(serialize_with = "crate::util::serialize_bytes_hex")]
        data: alloc::vec::Vec<u8>,
    },
    #[serde(rename = "opaque")]
    Opaque {
        psid: ProviderService,
        #[serde(serialize_with = "crate::util::serialize_bytes_hex")]
        data: alloc::vec::Vec<u8>,
    },
    #[serde(rename = "unsupported")]
    Unsupported {
        psid: ProviderService,
    },
}


impl From<&rasn_its::ieee1609dot2::base_types::PsidSsp> for super::perms::AppPermission {
    fn from(value: &rasn_its::ieee1609dot2::base_types::PsidSsp) -> Self {
        if value.psid.0 == *PSID_CAM
            && let Some(rasn_its::ieee1609dot2::base_types::ServiceSpecificPermissions::BitmapSsp(
                            ssp,
                        )) = &value.ssp
            && ssp.len() >= 1
        {
            if ssp[0] == 1 && ssp.len() == 3 {
                return Self::CAM(CAMPermissions::from_bitmap_v1(ssp));
            }
        }

        if value.psid.0 == *PSID_DENM
            && let Some(rasn_its::ieee1609dot2::base_types::ServiceSpecificPermissions::BitmapSsp(
                            ssp,
                        )) = &value.ssp
            && ssp.len() >= 1
        {
            if ssp[0] == 1 && ssp.len() == 4 {
                return Self::DENM(DENMPermissions::from_bitmap_v1(ssp));
            }
            if ssp[0] == 2 && ssp.len() == 5 {
                return Self::DENM(DENMPermissions::from_bitmap_v2(ssp));
            }
        }

        if value.psid.0 == *PSID_TLM
            && let Some(rasn_its::ieee1609dot2::base_types::ServiceSpecificPermissions::BitmapSsp(
                            ssp,
                        )) = &value.ssp
            && ssp.len() >= 1
        {
            if ssp[0] == 1 && ssp.len() == 2 {
                return Self::TLM(TLMPermissions::from_bitmap_v1(ssp));
            }
        }

        if value.psid.0 == *PSID_RLT
            && let Some(rasn_its::ieee1609dot2::base_types::ServiceSpecificPermissions::BitmapSsp(
                            ssp,
                        )) = &value.ssp
            && ssp.len() >= 1
        {
            if ssp[0] == 1 && ssp.len() == 2 {
                return Self::RLT(RLTPermissions::from_bitmap_v1(ssp));
            }
        }

        if value.psid.0 == *PSID_IVIM
            && let Some(rasn_its::ieee1609dot2::base_types::ServiceSpecificPermissions::BitmapSsp(
                            ssp,
                        )) = &value.ssp
            && ssp.len() >= 1
        {
            if ssp[0] == 1 && ssp.len() == 6 {
                return Self::IVIM(IVIMPermissions::from_bitmap_v1(ssp));
            }
        }

        if value.psid.0 == *PSID_TLC_REQ
            && let Some(rasn_its::ieee1609dot2::base_types::ServiceSpecificPermissions::BitmapSsp(
                            ssp,
                        )) = &value.ssp
            && ssp.len() >= 1
        {
            if ssp[0] == 2 && ssp.len() == 4 {
                return Self::TlcReq(TlcReqPermissions::from_bitmap_v2(ssp));
            }
        }

        if value.psid.0 == *PSID_TLC_STATUS
            && let Some(rasn_its::ieee1609dot2::base_types::ServiceSpecificPermissions::BitmapSsp(
                            ssp,
                        )) = &value.ssp
            && ssp.len() >= 1
        {
            if ssp[0] == 1 && ssp.len() == 1 {
                return Self::TlcStatus(TlcStatusPermissions::from_bitmap_v1(ssp));
            }
        }

        if value.psid.0 == *PSID_CRL
            && let Some(rasn_its::ieee1609dot2::base_types::ServiceSpecificPermissions::BitmapSsp(
                            ssp,
                        )) = &value.ssp
            && ssp.len() >= 1
        {
            if ssp[0] == 1 && ssp.len() == 1 {
                return Self::CertificateRevocationList(CertificateRevocationListPermissions::from_bitmap_v1(ssp));
            }
        }

        if value.psid.0 == *PSID_CTL
            && let Some(rasn_its::ieee1609dot2::base_types::ServiceSpecificPermissions::BitmapSsp(
                            ssp,
                        )) = &value.ssp
            && ssp.len() >= 1
        {
            if ssp[0] == 1 && ssp.len() == 2 {
                return Self::CertificateTrustList(
                    CertificateTrustListPermissions::from_bitmap_v1(ssp),
                );
            }
        }

        match &value.ssp {
            Some(rasn_its::ieee1609dot2::base_types::ServiceSpecificPermissions::Opaque(v)) => {
                Self::Opaque {
                    psid: (&value.psid).into(),
                    data: v.to_vec(),
                }
            }
            Some(rasn_its::ieee1609dot2::base_types::ServiceSpecificPermissions::BitmapSsp(v)) => {
                Self::UnknownBitmap {
                    psid: (&value.psid).into(),
                    data: v.to_vec(),
                }
            }
            _ => Self::Unsupported {
                psid: (&value.psid).into(),
            },
        }
    }
}


impl<'a> From<&'a AppPermission> for super::certs::RawAppPermission<'a> {
    fn from(value: &'a AppPermission) -> Self {
        match value {
            AppPermission::CAM(p) => Self::Bitmap { psid: ProviderService::CAM, data: &p._orig_value },
            AppPermission::DENM(p) => Self::Bitmap { psid: ProviderService::DENM, data: &p._orig_value },
            AppPermission::TLM(p) => Self::Bitmap { psid: ProviderService::TLM, data: &p._orig_value },
            AppPermission::RLT(p) => Self::Bitmap { psid: ProviderService::RLT, data: &p._orig_value },
            AppPermission::IVIM(p) => Self::Bitmap { psid: ProviderService::IVIM, data: &p._orig_value },
            AppPermission::TlcReq(p) => Self::Bitmap { psid: ProviderService::TLCReq, data: &p._orig_value },
            AppPermission::TlcStatus(p) => Self::Bitmap { psid: ProviderService::TLCStat, data: &p._orig_value },
            AppPermission::CertificateRevocationList(p) => Self::Bitmap { psid: ProviderService::CRL, data: &p._orig_value },
            AppPermission::CertificateTrustList(p) => Self::Bitmap { psid: ProviderService::CTL, data: &p._orig_value },
            AppPermission::UnknownBitmap { psid, data } => Self::Bitmap { psid: *psid, data: &data },
            AppPermission::Opaque { psid, data } => Self::Opaque { psid: *psid, data: &data },
            AppPermission::Unsupported { psid } => Self::Unsupported { psid: *psid },
        }
    }
}

pub fn cam_authorized(cam: &crate::asn::cam_pdu_descriptions::CAM, security_report: &super::message::SecurityReport) -> bool {
    if security_report.provider_service() != ProviderService::CAM {
        return false;
    }
    let Some(validated_chain) = security_report.validated_chain() else {
        return false;
    };
    let end_entity_cert = validated_chain.ee_cert();
    let Some(cam_perms) = end_entity_cert.get_cam_permission() else {
        return false;
    };

    match &cam.cam.cam_parameters.high_frequency_container {
        crate::asn::cam_pdu_descriptions::HighFrequencyContainer::basicVehicleContainerHighFrequency(vhf) => {
            if vhf.cen_dsrc_tolling_zone.is_some() && !cam_perms.cen_dsrc_tolling_zone {
                return false;
            }
        }
        _ => {}
    }
    match &cam.cam.cam_parameters.special_vehicle_container {
        Some(crate::asn::cam_pdu_descriptions::SpecialVehicleContainer::publicTransportContainer(_)) => {
            if !cam_perms.public_transport {
                return false;
            }
        }
        Some(crate::asn::cam_pdu_descriptions::SpecialVehicleContainer::specialTransportContainer(_)) => {
            if !cam_perms.special_transport {
                return false;
            }
        }
        Some(crate::asn::cam_pdu_descriptions::SpecialVehicleContainer::dangerousGoodsContainer(_)) => {
            if !cam_perms.dangerous_goods {
                return false;
            }
        }
        Some(crate::asn::cam_pdu_descriptions::SpecialVehicleContainer::roadWorksContainerBasic(rw)) => {
            if !cam_perms.roadworks {
                return false;
            }
            if rw.closed_lanes.is_some() && !cam_perms.closed_lanes {
                return false;
            }
        }
        Some(crate::asn::cam_pdu_descriptions::SpecialVehicleContainer::rescueContainer(_)) => {
            if !cam_perms.rescue {
                return false;
            }
        }
        Some(crate::asn::cam_pdu_descriptions::SpecialVehicleContainer::emergencyContainer(e)) => {
            if !cam_perms.emergency {
                return false;
            }
            if let Some(ep) = &e.emergency_priority {
                if (ep.0[0]) && !cam_perms.request_right_of_way {
                    return false;
                }
                if (ep.0[1]) && !cam_perms.request_free_crossing {
                    return false;
                }
            }
        }
        Some(crate::asn::cam_pdu_descriptions::SpecialVehicleContainer::safetyCarContainer(sc)) => {
            if !cam_perms.safety_car {
                return false;
            }
            if let Some(tr) = &sc.traffic_rule {
                if (*tr == crate::asn::etsi_its_cdd::TrafficRule::noPassing) && !cam_perms.no_passing {
                    return false;
                }
                if (*tr == crate::asn::etsi_its_cdd::TrafficRule::noPassingForTrucks) && !cam_perms.no_passing_for_trucks {
                    return false;
                }
            }
            if sc.speed_limit.is_some() && !cam_perms.speed_limit {
                return false;
            }
        }
        _ => {}
    }
    true
}