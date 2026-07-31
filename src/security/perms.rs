lazy_static::lazy_static! {
    pub(crate) static ref PSID_CAM: rasn::types::Integer = rasn::types::Integer::from(36);
    pub(crate) static ref PSID_DENM: rasn::types::Integer = rasn::types::Integer::from(37);
    pub(crate) static ref PSID_TLM: rasn::types::Integer = rasn::types::Integer::from(137);
    pub(crate) static ref PSID_RLT: rasn::types::Integer = rasn::types::Integer::from(138);
    pub(crate) static ref PSID_IVIM: rasn::types::Integer = rasn::types::Integer::from(139);
    pub(crate) static ref PSID_TLC_REQ: rasn::types::Integer = rasn::types::Integer::from(140);
    pub(crate) static ref PSID_GN_MGMT: rasn::types::Integer = rasn::types::Integer::from(141);
    pub(crate) static ref PSID_CRL: rasn::types::Integer = rasn::types::Integer::from(622);
    pub(crate) static ref PSID_CERT_REQ: rasn::types::Integer = rasn::types::Integer::from(623);
    pub(crate) static ref PSID_CTL: rasn::types::Integer = rasn::types::Integer::from(624);
    pub(crate) static ref PSID_TLC_STATUS: rasn::types::Integer = rasn::types::Integer::from(637);
    pub(crate) static ref PSID_VRU: rasn::types::Integer = rasn::types::Integer::from(638);
    pub(crate) static ref PSID_CP: rasn::types::Integer = rasn::types::Integer::from(639);
    pub(crate) static ref PSID_MR: rasn::types::Integer = rasn::types::Integer::from(1618);
    pub(crate) static ref PSID_POI: rasn::types::Integer = rasn::types::Integer::from(1619);
    pub(crate) static ref PSID_SA: rasn::types::Integer = rasn::types::Integer::from(540801);
}

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
    signal_phase_timing: bool,
    public_transport_prioritization_status: bool,
    maneuver_assisting_information: bool,
    #[serde(skip_serializing)]
    _orig_value: alloc::vec::Vec<u8>,
}

impl TLMPermissions {
    fn from_bitmap_v1(ssp: &rasn_its::ieee1609dot2::base_types::BitmapSsp) -> Self {
        Self {
            signal_phase_timing: ssp[1] & 0x80 != 0,
            public_transport_prioritization_status: ssp[1] & 0x40 != 0,
            maneuver_assisting_information: ssp[1] & 0x20 != 0,
            _orig_value: ssp.0.to_vec(),
        }
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct RLTPermissions {
    intersections_geometry: bool,
    road_geometry: bool,
    #[serde(skip_serializing)]
    _orig_value: alloc::vec::Vec<u8>,
}

impl RLTPermissions {
    fn from_bitmap_v1(ssp: &rasn_its::ieee1609dot2::base_types::BitmapSsp) -> Self {
        Self {
            intersections_geometry: ssp[1] & 0x80 != 0,
            road_geometry: ssp[1] & 0x40 != 0,
            _orig_value: ssp.0.to_vec(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IVIMProvider(crate::asn::efc_data_dictionary::Provider);

impl core::cmp::Ord for IVIMProvider {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.country_code.0.cmp(&other.0.country_code.0)
            .then_with(|| self.0.provider_identifier.0.cmp(&other.0.provider_identifier.0))
    }
}

impl core::cmp::PartialOrd for IVIMProvider {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl serde::Serialize for IVIMProvider {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("Provider", 2)?;
        s.serialize_field("country_code", &crate::util::decode_ita2(&self.0.country_code.0))?;
        s.serialize_field("provider_identifier", &self.0.provider_identifier.0)?;
        s.end()
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct IVIMPermissions {
    service_provider: IVIMProvider,
    vienna_convention_road_sign: bool,
    iso_14823_traffic_sign_pictogram_danger: bool,
    iso_14823_traffic_sign_pictogram_regulatory: bool,
    iso_14823_traffic_sign_pictogram_informative: bool,
    iso_14823_public_facilities_pictogram: bool,
    iso_14823_ambient_conditions_pictogram: bool,
    iso_14823_road_conditions_pictogram: bool,
    itis_codes: bool,
    lane_status: bool,
    road_configuration: bool,
    text: bool,
    layout: bool,
    ivi_status_negotiation: bool,
    automated_vehicle: bool,
    map_location: bool,
    road_surface: bool,
    #[serde(skip_serializing)]
    _orig_value: alloc::vec::Vec<u8>,
}

impl IVIMPermissions {
    fn from_bitmap_v1(ssp: &rasn_its::ieee1609dot2::base_types::BitmapSsp) -> Self {
        Self {
            service_provider: IVIMProvider(rasn::uper::decode(&ssp.0[1..4]).unwrap()),
            vienna_convention_road_sign: ssp[4] & 0x80 != 0,
            iso_14823_traffic_sign_pictogram_danger: ssp[4] & 0x40 != 0,
            iso_14823_traffic_sign_pictogram_regulatory: ssp[4] & 0x20 != 0,
            iso_14823_traffic_sign_pictogram_informative: ssp[4] & 0x10 != 0,
            iso_14823_public_facilities_pictogram: ssp[4] & 0x08 != 0,
            iso_14823_ambient_conditions_pictogram: ssp[4] & 0x04 != 0,
            iso_14823_road_conditions_pictogram: ssp[4] & 0x02 != 0,
            itis_codes: ssp[4] & 0x01 != 0,
            lane_status: ssp[5] & 0x80 != 0,
            road_configuration: ssp[5] & 0x40 != 0,
            text: ssp[5] & 0x20 != 0,
            layout: ssp[5] & 0x10 != 0,
            ivi_status_negotiation: ssp[5] & 0x08 != 0,
            automated_vehicle: ssp[5] & 0x04 != 0,
            map_location: ssp[5] & 0x02 != 0,
            road_surface: ssp[5] & 0x01 != 0,
            _orig_value: ssp.0.to_vec(),
        }
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct TlcReqPermissions {
    signal_request: bool,
    requestor_public_transport: bool,
    requestor_special_transport: bool,
    requestor_dangerous_goods: bool,
    requestor_road_work: bool,
    requestor_road_rescue: bool,
    requestor_emergency: bool,
    requestor_safety_car: bool,
    requestor_truck: bool,
    requestor_motorcycle: bool,
    requestor_police: bool,
    requestor_fire: bool,
    requestor_ambulance: bool,
    requestor_dot: bool,
    requestor_transit: bool,
    requestor_slow_moving: bool,
    requestor_cyclist: bool,
    requestor_pedestrian: bool,
    requestor_military: bool,
    requestor_tram: bool,
    ocit: bool,
    #[serde(skip_serializing)]
    _orig_value: alloc::vec::Vec<u8>,
}

impl TlcReqPermissions {
    fn from_bitmap_v2(ssp: &rasn_its::ieee1609dot2::base_types::BitmapSsp) -> Self {
        Self {
            signal_request: ssp[1] & 0x80 != 0,
            requestor_public_transport: ssp[1] & 0x40 != 0,
            requestor_special_transport: ssp[1] & 0x20 != 0,
            requestor_dangerous_goods: ssp[1] & 0x10 != 0,
            requestor_road_work: ssp[1] & 0x08 != 0,
            requestor_road_rescue: ssp[1] & 0x04 != 0,
            requestor_emergency: ssp[1] & 0x02 != 0,
            requestor_safety_car: ssp[1] & 0x01 != 0,
            requestor_truck: ssp[2] & 0x80 != 0,
            requestor_motorcycle: ssp[2] & 0x40 != 0,
            requestor_police: ssp[2] & 0x20 != 0,
            requestor_fire: ssp[2] & 0x10 != 0,
            requestor_ambulance: ssp[2] & 0x08 != 0,
            requestor_dot: ssp[2] & 0x04 != 0,
            requestor_transit: ssp[2] & 0x02 != 0,
            requestor_slow_moving: ssp[2] & 0x01 != 0,
            requestor_cyclist: ssp[2] & 0x80 != 0,
            requestor_pedestrian: ssp[2] & 0x40 != 0,
            requestor_military: ssp[2] & 0x20 != 0,
            requestor_tram: ssp[2] & 0x10 != 0,
            ocit: ssp[2] & 0x08 != 0,
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
pub struct CertificateRequestPermissions {
    pub enrollment_request: bool,
    pub authorization_request: bool,
    pub authorization_validation_request: bool,
    pub authorization_response: bool,
    pub authorization_validation_response: bool,
    pub enrollment_response: bool,
    pub ca_certificate_request: bool,
    #[serde(skip_serializing)]
    _orig_value: alloc::vec::Vec<u8>,
}

impl CertificateRequestPermissions {
    fn from_bitmap_v1(ssp: &rasn_its::ieee1609dot2::base_types::BitmapSsp) -> Self {
        Self {
            enrollment_request: ssp[1] & 0x80 != 0,
            authorization_request: ssp[1] & 0x40 != 0,
            authorization_validation_request: ssp[1] & 0x20 != 0,
            authorization_response: ssp[1] & 0x10 != 0,
            authorization_validation_response: ssp[1] & 0x08 != 0,
            enrollment_response: ssp[1] & 0x04 != 0,
            ca_certificate_request: ssp[1] & 0x02 != 0,
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
    #[serde(rename = "certificate_request")]
    CertificateRequest(CertificateRequestPermissions),
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

        if value.psid.0 == *PSID_CERT_REQ
            && let Some(rasn_its::ieee1609dot2::base_types::ServiceSpecificPermissions::BitmapSsp(
                            ssp,
                        )) = &value.ssp
            && ssp.len() >= 1
        {
            if ssp[0] == 1 && ssp.len() == 2 {
                return Self::CertificateRequest(
                    CertificateRequestPermissions::from_bitmap_v1(ssp),
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
            AppPermission::CertificateRequest(p) => Self::Bitmap { psid: ProviderService::CertReq, data: &p._orig_value },
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

pub fn denm_authorized(denm: &crate::asn::denm_pdu_description::DENM, security_report: &super::message::SecurityReport) -> bool {
    if security_report.provider_service() != ProviderService::DENM {
        return false;
    }
    let Some(validated_chain) = security_report.validated_chain() else {
        return false;
    };
    let end_entity_cert = validated_chain.ee_cert();
    let Some(denm_perms) = end_entity_cert.get_denm_permission() else {
        return false;
    };

    if let Some(situation) = &denm.denm.situation {
        match situation.event_type.cc_and_scc {
            crate::asn::etsi_its_cdd::CauseCodeChoice::trafficCondition1(_) => {
                if !denm_perms.traffic_condition {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::accident2(_) => {
                if !denm_perms.accident {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::roadworks3(_) => {
                if !denm_perms.roadworks {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::impassability5(_) => {
                if !denm_perms.impassability {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::adhesion6(_) => {
                if !denm_perms.adverse_weather_condition_adhesion {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::aquaplaning7(_) => {
                if !denm_perms.aquaplaning {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::hazardousLocation_SurfaceCondition9(_) => {
                if !denm_perms.hazardous_location_surface_condition {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::hazardousLocation_ObstacleOnTheRoad10(_) => {
                if !denm_perms.hazardous_location_obstacle_on_the_road {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::hazardousLocation_AnimalOnTheRoad11(_) => {
                if !denm_perms.hazardous_location_animal_on_the_road {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::humanPresenceOnTheRoad12(_) => {
                if !denm_perms.human_presence_on_the_road {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::wrongWayDriving14(_) => {
                if !denm_perms.wrong_way_driving {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::rescueRecoveryAndMaintenanceWorkInProgress15(_) => {
                if !denm_perms.rescue_and_recovery_work_in_progress {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::adverseWeatherCondition_Wind17(_) => {
                if !denm_perms.adverse_weather_condition_extreme_weather_condition {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::adverseWeatherCondition_Visibility18(_) => {
                if !denm_perms.adverse_weather_condition_visibility {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::adverseWeatherCondition_Precipitation19(_) => {
                if !denm_perms.adverse_weather_condition_precipitation {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::slowVehicle26(_) => {
                if !denm_perms.slow_vehicle {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::dangerousEndOfQueue27(_) => {
                if !denm_perms.dangerous_end_of_queue {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::vehicleBreakdown91(_) => {
                if !denm_perms.vehicle_breakdown {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::postCrash92(_) => {
                if !denm_perms.post_crash {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::humanProblem93(_) => {
                if !denm_perms.human_problem {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::stationaryVehicle94(_) => {
                if !denm_perms.stationary_vehicle {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::emergencyVehicleApproaching95(_) => {
                if !denm_perms.emergency_vehicle_approaching {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::hazardousLocation_DangerousCurve96(_) => {
                if !denm_perms.hazardous_location_dangerous_curve {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::collisionRisk97(_) => {
                if !denm_perms.collision_risk {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::signalViolation98(_) => {
                if !denm_perms.signal_violation {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::dangerousSituation99(_) => {
                if !denm_perms.dangerous_situation {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::publicTransportVehicleApproaching28(_) => {
                if !denm_perms.public_transport_vehicle_approaching {
                    return false;
                }
            }
            crate::asn::etsi_its_cdd::CauseCodeChoice::railwayLevelCrossing100(_) => {
                if !denm_perms.railway_level_crossing {
                    return false;
                }
            },
            _ => {}
        }
    }

    true
}

pub fn rlt_authorized(mapem: &crate::asn::mapem_pdu_descriptions::MAPEM, security_report: &super::message::SecurityReport) -> bool {
    if security_report.provider_service() != ProviderService::RLT {
        return false;
    }
    let Some(validated_chain) = security_report.validated_chain() else {
        return false;
    };
    let end_entity_cert = validated_chain.ee_cert();
    let Some(rtl_perms) = end_entity_cert.get_rlt_permission() else {
        return false;
    };

    if mapem.map.intersections.is_some() && !rtl_perms.intersections_geometry {
        return false;
    }
    if mapem.map.road_segments.is_some() && !rtl_perms.road_geometry {
        return false;
    }

    true
}

pub fn tlm_authorized(spatem: &crate::asn::spatem_pdu_descriptions::SPATEM, security_report: &super::message::SecurityReport) -> bool {
    if security_report.provider_service() != ProviderService::TLM {
        return false;
    }
    let Some(validated_chain) = security_report.validated_chain() else {
        return false;
    };
    let end_entity_cert = validated_chain.ee_cert();
    let Some(tlm_perms) = end_entity_cert.get_tlm_permission() else {
        return false;
    };

    for intersection in spatem.spat.intersections.0.iter() {
        if !intersection.states.0.is_empty() && !tlm_perms.signal_phase_timing {
            return false;
        }
        if intersection.maneuver_assist_list.is_some() && !tlm_perms.maneuver_assisting_information {
            return false;
        }
        for state in intersection.states.0.iter() {
            if state.maneuver_assist_list.is_some() && !tlm_perms.maneuver_assisting_information {
                return false;
            }
        }
        if let Some(regional) = &intersection.regional {
            for ext in regional.iter() {
                if ext.region_id == crate::asn::etsi_its_dsrc::ADD_GRP_C {
                    let Ok(ext_val) = rasn::uper::decode::<crate::asn::etsi_its_dsrc_add_grp_c::IntersectionStateAddGrpC>(ext.reg_ext_value.as_bytes()) else {
                        return false;
                    };
                    if ext_val.active_prioritizations.is_some() && !tlm_perms.public_transport_prioritization_status {
                        return false;
                    }
                }
            }
        }
    }

    true
}

pub fn ivim_authorized(ivim: &crate::asn::ivim_pdu_descriptions::IVIM, security_report: &super::message::SecurityReport) -> bool {
    if security_report.provider_service() != ProviderService::IVIM {
        return false;
    }
    let Some(validated_chain) = security_report.validated_chain() else {
        return false;
    };
    let end_entity_cert = validated_chain.ee_cert();
    let Some(ivim_perms) = end_entity_cert.get_ivim_permission() else {
        return false;
    };

    if ivim.ivi.mandatory.service_provider_id != ivim_perms.service_provider.0 {
        return false;
    }

    if ivim.ivi.mandatory.ivi_status.0 == 1 && !ivim_perms.ivi_status_negotiation {
        return false;
    }

    if let Some(optional) = &ivim.ivi.optional {
        for container in &optional.0 {
            match container {
                crate::asn::ivi::IviContainer::giv(gic) => {
                    for gic_part in &gic.0 {
                        for rsc in &gic_part.road_sign_codes.0 {
                            match &rsc.code {
                                crate::asn::ivi::RSCodeCode::viennaConvention(_) => {
                                    if !ivim_perms.vienna_convention_road_sign {
                                        return false;
                                    }
                                }
                                crate::asn::ivi::RSCodeCode::iso14823(iso14823) => {
                                    match iso14823.pictogram_code.service_category_code {
                                        crate::asn::ivi::ISO14823CodePictogramCodeServiceCategoryCode::trafficSignPictogram(tsp) => {
                                            if tsp == crate::asn::ivi::ISO14823CodePictogramCodeServiceCategoryCodeTrafficSignPictogram::dangerWarning && !ivim_perms.iso_14823_traffic_sign_pictogram_danger {
                                                return false;
                                            } else if tsp == crate::asn::ivi::ISO14823CodePictogramCodeServiceCategoryCodeTrafficSignPictogram::regulatory && !ivim_perms.iso_14823_traffic_sign_pictogram_regulatory {
                                                return false;
                                            } else if tsp == crate::asn::ivi::ISO14823CodePictogramCodeServiceCategoryCodeTrafficSignPictogram::informative && !ivim_perms.iso_14823_traffic_sign_pictogram_informative {
                                                return false;
                                            }
                                        }
                                        crate::asn::ivi::ISO14823CodePictogramCodeServiceCategoryCode::publicFacilitiesPictogram(_) => {
                                            if !ivim_perms.iso_14823_public_facilities_pictogram {
                                                return false;
                                            }
                                        }
                                        crate::asn::ivi::ISO14823CodePictogramCodeServiceCategoryCode::ambientOrRoadConditionPictogram(arc) => {
                                            if arc == crate::asn::ivi::ISO14823CodePictogramCodeServiceCategoryCodeAmbientOrRoadConditionPictogram::ambientCondition && !ivim_perms.iso_14823_ambient_conditions_pictogram {
                                                return false;
                                            } else if arc == crate::asn::ivi::ISO14823CodePictogramCodeServiceCategoryCodeAmbientOrRoadConditionPictogram::roadCondition && !ivim_perms.iso_14823_road_conditions_pictogram {
                                                return false;
                                            }
                                        },
                                        _ => {}
                                    }
                                },
                                crate::asn::ivi::RSCodeCode::itisCodes(_) => {
                                    if !ivim_perms.itis_codes {
                                        return false;
                                    }
                                },
                                _ => {}
                            }
                        }
                        if gic_part.lane_status.is_some() && !ivim_perms.lane_status {
                            return false;
                        }
                    }
                },
                crate::asn::ivi::IviContainer::rcc(_) => {
                    if !ivim_perms.road_configuration {
                        return false;
                    }
                }
                crate::asn::ivi::IviContainer::tc(_) => {
                    if !ivim_perms.text {
                        return false;
                    }
                }
                crate::asn::ivi::IviContainer::lac(_) => {
                    if !ivim_perms.layout {
                        return false;
                    }
                }
                crate::asn::ivi::IviContainer::avc(_) => {
                    if !ivim_perms.automated_vehicle {
                        return false;
                    }
                }
                crate::asn::ivi::IviContainer::mlc(_) => {
                    if !ivim_perms.map_location {
                        return false;
                    }
                }
                crate::asn::ivi::IviContainer::rsc(_) => {
                    if !ivim_perms.road_surface {
                        return false;
                    }
                }
                _ => {}
            }
        }
    }

    true
}

pub fn tlc_req_authorized(srem: &crate::asn::srem_pdu_descriptions::SREM, security_report: &super::message::SecurityReport) -> bool {
    if security_report.provider_service() != ProviderService::TLCReq {
        return false;
    }
    let Some(validated_chain) = security_report.validated_chain() else {
        return false;
    };
    let end_entity_cert = validated_chain.ee_cert();
    let Some(tlc_req_perms) = end_entity_cert.get_tlc_req_permission() else {
        return false;
    };

    if srem.srm.requests.is_some() && !tlc_req_perms.signal_request {
        return false;
    }
    if let Some(r_type) = &srem.srm.requestor.r_type {
        if r_type.role == crate::asn::etsi_its_dsrc::BasicVehicleRole::publicTransport && !tlc_req_perms.requestor_public_transport {
            return false;
        } else if r_type.role == crate::asn::etsi_its_dsrc::BasicVehicleRole::specialTransport && !tlc_req_perms.requestor_special_transport {
            return false;
        } else if r_type.role == crate::asn::etsi_its_dsrc::BasicVehicleRole::dangerousGoods && !tlc_req_perms.requestor_dangerous_goods {
            return false;
        } else if r_type.role == crate::asn::etsi_its_dsrc::BasicVehicleRole::roadWork && !tlc_req_perms.requestor_road_work {
            return false;
        } else if r_type.role == crate::asn::etsi_its_dsrc::BasicVehicleRole::roadRescue && !tlc_req_perms.requestor_road_rescue {
            return false;
        } else if r_type.role == crate::asn::etsi_its_dsrc::BasicVehicleRole::emergency && !tlc_req_perms.requestor_emergency {
            return false;
        } else if r_type.role == crate::asn::etsi_its_dsrc::BasicVehicleRole::safetyCar && !tlc_req_perms.requestor_safety_car {
            return false;
        } else if r_type.role == crate::asn::etsi_its_dsrc::BasicVehicleRole::truck && !tlc_req_perms.requestor_truck {
            return false;
        } else if r_type.role == crate::asn::etsi_its_dsrc::BasicVehicleRole::motorcycle && !tlc_req_perms.requestor_motorcycle {
            return false;
        } else if r_type.role == crate::asn::etsi_its_dsrc::BasicVehicleRole::police && !tlc_req_perms.requestor_police {
            return false;
        } else if r_type.role == crate::asn::etsi_its_dsrc::BasicVehicleRole::fire && !tlc_req_perms.requestor_fire {
            return false;
        } else if r_type.role == crate::asn::etsi_its_dsrc::BasicVehicleRole::ambulance && !tlc_req_perms.requestor_ambulance {
            return false;
        } else if r_type.role == crate::asn::etsi_its_dsrc::BasicVehicleRole::dot && !tlc_req_perms.requestor_dot {
            return false;
        } else if r_type.role == crate::asn::etsi_its_dsrc::BasicVehicleRole::transit && !tlc_req_perms.requestor_transit {
            return false;
        } else if r_type.role == crate::asn::etsi_its_dsrc::BasicVehicleRole::slowMoving && !tlc_req_perms.requestor_slow_moving {
            return false;
        } else if r_type.role == crate::asn::etsi_its_dsrc::BasicVehicleRole::cyclist && !tlc_req_perms.requestor_cyclist {
            return false;
        } else if r_type.role == crate::asn::etsi_its_dsrc::BasicVehicleRole::pedestrian && !tlc_req_perms.requestor_pedestrian {
            return false;
        } else if r_type.role == crate::asn::etsi_its_dsrc::BasicVehicleRole::military && !tlc_req_perms.requestor_military {
            return false;
        } else if r_type.role == crate::asn::etsi_its_dsrc::BasicVehicleRole::tram && !tlc_req_perms.requestor_tram {
            return false;
        }
    }
    if srem.srm.requestor.ocit.is_some() && !tlc_req_perms.ocit {
        return false;
    }

    true
}

pub fn tlc_status_authorized(security_report: &super::message::SecurityReport) -> bool {
    if security_report.provider_service() != ProviderService::TLCStat {
        return false;
    }
    let Some(validated_chain) = security_report.validated_chain() else {
        return false;
    };
    let end_entity_cert = validated_chain.ee_cert();
    end_entity_cert.has_tlc_status_permission()
}