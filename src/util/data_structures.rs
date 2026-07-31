use c_its::geo_networking;

#[derive(serde::Serialize)]
pub struct ITSFrame<'a> {
    #[serde(serialize_with = "c_its::util::serialize_mac_address")]
    pub wifi_source_address: ieee80211::mac_parser::MACAddress,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub geo_networking: GeoNetworkingFrame<'a>,
}

#[derive(serde::Serialize)]
pub struct GeoNetworkingFrame<'a> {
    pub lifetime_millis: u128,
    pub remaining_hop_limit: u8,
    pub maximum_hop_limit: u8,
    pub is_mobile: bool,
    pub traffic_class: geo_networking::TrafficClass,
    pub header: PacketHeader,
    pub security: Option<c_its::security::SecurityReport>,
    pub data: Option<PacketData<'a>>,
}

#[derive(serde::Serialize)]
#[serde(tag = "type")]
pub enum PacketHeader {
    #[serde(rename = "geo_anycast")]
    GeoAnycast {
        source_position: LongPositionVector,
        sequence: u16,
        area_centre: geo_networking::LatLong,
        area: geo_networking::GeoArea,
    },
    #[serde(rename = "geo_broadcast")]
    GeoBroadcast {
        source_position: LongPositionVector,
        sequence: u16,
        area_centre: geo_networking::LatLong,
        area: geo_networking::GeoArea,
    },
    #[serde(rename = "multi_hop_broadcast")]
    MultiHopBroadcast {
        source_position: LongPositionVector,
        sequence: u16,
    },
    #[serde(rename = "single_hop_broadcast")]
    SingleHopBroadcast {
        source_position: LongPositionVector,
        dcc: geo_networking::DistributedCongestionControlData,
    },
    #[serde(rename = "beacon")]
    Beacon { source_position: LongPositionVector },
}

#[derive(serde::Serialize)]
#[serde(tag = "type")]
pub enum PacketData<'a> {
    #[serde(rename = "btp_a")]
    BtpA {
        destination_port: u16,
        source_port: u16,
        #[serde(serialize_with = "c_its::util::serialize_bytes")]
        data: &'a [u8],
    },
    #[serde(rename = "btp_b")]
    BtpB {
        destination_port: u16,
        destination_port_info: u16,
        data: InnerData<'a>,
    },
    #[serde(rename = "ipv6")]
    Ipv6(#[serde(serialize_with = "c_its::util::serialize_bytes")] &'a [u8]),
}

#[derive(serde::Serialize)]
#[serde(tag = "type", content = "data")]
pub enum InnerData<'a> {
    #[serde(rename = "cam")]
    CAM {
        data: serde_json::Value,
        security_authorized: bool,
    },
    #[serde(rename = "denm")]
    DENM {
        data: serde_json::Value,
        security_authorized: bool,
    },
    #[serde(rename = "mapem")]
    MAPEM {
        data: serde_json::Value,
        security_authorized: bool,
    },
    #[serde(rename = "spatem")]
    SPATEM {
        data: serde_json::Value,
        security_authorized: bool,
    },
    #[serde(rename = "ivim")]
    IVIM {
        data: serde_json::Value,
        security_authorized: bool,
    },
    #[serde(rename = "tlc_req")]
    TlcReq {
        data: serde_json::Value,
        security_authorized: bool,
    },
    #[serde(rename = "tlc_status")]
    TlcStatus {
        data: serde_json::Value,
        security_authorized: bool,
    },
    #[serde(rename = "raw")]
    Raw {
        #[serde(serialize_with = "c_its::util::serialize_bytes")]
        data: &'a [u8],
    },
}

#[derive(serde::Serialize)]
pub struct GnAddress {
    pub manually_configured: bool,
    pub traffic_participant_type: TrafficParticipant,
    #[serde(serialize_with = "c_its::util::serialize_mac_address")]
    pub mac_address: ieee80211::mac_parser::MACAddress,
}

pub enum TrafficParticipant {
    Unknown,
    Pedestrian,
    Cyclist,
    Moped,
    Motorcycle,
    PassengerCar,
    Bus,
    LightTruck,
    HeavyTruck,
    Trailer,
    SpecialVehicle,
    Tram,
    LightVruVehicle,
    Animal,
    Agricultural,
    Infrastructure,
    Other(u8),
}

impl serde::Serialize for TrafficParticipant {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            TrafficParticipant::Unknown => serializer.serialize_str("unknown"),
            TrafficParticipant::Pedestrian => serializer.serialize_str("pedestrian"),
            TrafficParticipant::Cyclist => serializer.serialize_str("cyclist"),
            TrafficParticipant::Moped => serializer.serialize_str("moped"),
            TrafficParticipant::Motorcycle => serializer.serialize_str("motorcycle"),
            TrafficParticipant::PassengerCar => serializer.serialize_str("passenger_car"),
            TrafficParticipant::Bus => serializer.serialize_str("bus"),
            TrafficParticipant::LightTruck => serializer.serialize_str("light_truck"),
            TrafficParticipant::HeavyTruck => serializer.serialize_str("heavy_truck"),
            TrafficParticipant::Trailer => serializer.serialize_str("trailer"),
            TrafficParticipant::SpecialVehicle => serializer.serialize_str("special_vehicle"),
            TrafficParticipant::Tram => serializer.serialize_str("tram"),
            TrafficParticipant::LightVruVehicle => serializer.serialize_str("light_vru_vehicle"),
            TrafficParticipant::Animal => serializer.serialize_str("animal"),
            TrafficParticipant::Agricultural => serializer.serialize_str("agricultural"),
            TrafficParticipant::Infrastructure => serializer.serialize_str("infrastructure"),
            TrafficParticipant::Other(v) => serializer.serialize_u8(*v),
        }
    }
}

#[derive(serde::Serialize)]
pub struct LongPositionVector {
    pub address: GnAddress,
    pub position: geo_networking::LatLong,
    pub accurate_position: bool,
    pub acquisition_time_tai_ms: u32,
    pub acquisition_time_utc: chrono::DateTime<chrono::offset::Utc>,
    pub speed_ms: f32,
    pub heading_deg: f32,
}

impl From<&geo_networking::LongPositionVector> for LongPositionVector {
    fn from(v: &geo_networking::LongPositionVector) -> Self {
        Self {
            address: GnAddress {
                manually_configured: v.address.manually_configured,
                traffic_participant_type: match v.address.traffic_participant_type {
                    0 => TrafficParticipant::Unknown,
                    1 => TrafficParticipant::Pedestrian,
                    2 => TrafficParticipant::Cyclist,
                    3 => TrafficParticipant::Moped,
                    4 => TrafficParticipant::Motorcycle,
                    5 => TrafficParticipant::PassengerCar,
                    6 => TrafficParticipant::Bus,
                    7 => TrafficParticipant::LightTruck,
                    8 => TrafficParticipant::HeavyTruck,
                    9 => TrafficParticipant::Trailer,
                    10 => TrafficParticipant::SpecialVehicle,
                    11 => TrafficParticipant::Tram,
                    12 => TrafficParticipant::LightVruVehicle,
                    13 => TrafficParticipant::Animal,
                    14 => TrafficParticipant::Agricultural,
                    15 => TrafficParticipant::Infrastructure,
                    o => TrafficParticipant::Other(o),
                },
                mac_address: v.address.mac_address,
            },
            position: v.position,
            accurate_position: v.accurate_position,
            acquisition_time_tai_ms: v.acquisition_time.0,
            acquisition_time_utc: c_its::util::chrono_from_tai(
                &v.acquisition_time.to_datetime(&chrono::Utc::now()),
            ),
            speed_ms: v.speed_ms,
            heading_deg: v.heading_deg,
        }
    }
}
