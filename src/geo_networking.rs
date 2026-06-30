use alloc::borrow::ToOwned;
use alloc::vec::Vec;

const GN_TIME_EPOCH: i64 = 1072915168;
pub type GnTaiTime = tai_time::TaiTime<GN_TIME_EPOCH>;

pub const LEAP_SECONDS: i64 = 37;

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct Time(pub u32);

const WRAP_MS: i128 = 1i128 << 32;

impl Time {
    pub fn to_datetime<Tz: chrono::TimeZone>(&self, now: &chrono::DateTime<Tz>) -> GnTaiTime {

        let now = GnTaiTime::from_chrono_date_time(now, LEAP_SECONDS);
        let now_ms = (now.as_secs() as i128 * 1000) + (now.subsec_nanos() / 1000000) as i128;

        let base_ms = self.0 as i128;
        let k = (now_ms - base_ms).div_euclid(WRAP_MS);

        let mut best: Option<(i128, i128)> = None;
        for n in [k - 1, k, k + 1] {
            let candidate_ms = base_ms + n * WRAP_MS;
            let dist = (candidate_ms - now_ms).abs();
            if best.is_none_or(|(best_dist, _)| dist < best_dist) {
                best = Some((dist, candidate_ms));
            }
        }

        let best_ms = best.expect("at least one candidate").1;
        GnTaiTime::new((best_ms / 1000) as i64, (best_ms % 1000) as u32 * 1000000).unwrap()
    }

    pub fn from_datetime<Tz: chrono::TimeZone>(dt: &chrono::DateTime<Tz>) -> Self {
        let dt = GnTaiTime::from_chrono_date_time(dt, LEAP_SECONDS);
        let dt_ms = (dt.as_secs() as i128 * 1000) + (dt.subsec_nanos() / 1000000) as i128;
        Self((dt_ms % WRAP_MS) as u32)
    }
}

#[derive(Debug)]
pub struct BasicHeader {
    pub lifetime: core::time::Duration,
    pub remaining_hop_limit: u8,
}

#[derive(Debug)]
pub struct GeoNetworkingFrame<'a> {
    pub basic_header: BasicHeader,
    pub data: PacketType<'a>,
}

#[derive(Debug)]
pub enum PacketType<'a> {
    Unsecured(CommonHeader<'a>),
    Secured(SignedPacket),
}

#[derive(Debug)]
pub struct SignedPacket(rasn_its::ieee1609dot2::SignedData);

#[derive(Debug, Clone)]
pub struct CommonHeader<'a> {
    pub traffic_class: TrafficClass,
    pub is_mobile: bool,
    pub maximum_hop_limit: u8,
    pub data: PacketData<'a>,
}

impl CommonHeader<'_> {
    fn into_owned(self) -> CommonHeader<'static> {
        CommonHeader {
            traffic_class: self.traffic_class,
            is_mobile: self.is_mobile,
            maximum_hop_limit: self.maximum_hop_limit,
            data: self.data.into_owned(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum PacketData<'a> {
    GeoAnycast(GeoCastPacket<'a>),
    GeoBroadcast(GeoCastPacket<'a>),
    MultiHopBroadcast(MultipHopBroadcastPacket<'a>),
    SingleHopBroadcast(SingleHopBroadcastPacket<'a>),
    Beacon(BeaconPacket)
}

impl PacketData<'_> {
    fn into_owned(self) -> PacketData<'static> {
        match self {
            Self::GeoAnycast(p) => PacketData::GeoAnycast(p.into_owned()),
            Self::GeoBroadcast(p) => PacketData::GeoBroadcast(p.into_owned()),
            Self::MultiHopBroadcast(p) => PacketData::MultiHopBroadcast(p.into_owned()),
            Self::SingleHopBroadcast(p) => PacketData::SingleHopBroadcast(p.into_owned()),
            Self::Beacon(p) => PacketData::Beacon(p),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GeoCastPacket<'a> {
    pub source_position: LongPositionVector,
    pub sequence: u16,
    pub area_centre: LatLong,
    pub area: GeoArea,
    pub inner_data: InnerData<'a>
}

impl GeoCastPacket<'_> {
    fn into_owned(self) -> GeoCastPacket<'static> {
        GeoCastPacket {
            source_position: self.source_position,
            sequence: self.sequence,
            area_centre: self.area_centre,
            area: self.area,
            inner_data: self.inner_data.into_owned()
        }
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum GeoArea {
    Circle {
        radius: u16,
    },
    Rectangle {
        width: u16,
        height: u16,
        angle: u16,
    },
    Ellipse {
        a: u16,
        b: u16,
        angle: u16
    }
}

#[derive(Debug, Clone)]
pub struct MultipHopBroadcastPacket<'a> {
    pub source_position: LongPositionVector,
    pub sequence: u16,
    pub inner_data: InnerData<'a>
}

impl MultipHopBroadcastPacket<'_> {
    fn into_owned(self) -> MultipHopBroadcastPacket<'static> {
        MultipHopBroadcastPacket {
            source_position: self.source_position,
            sequence: self.sequence,
            inner_data: self.inner_data.into_owned()
        }
    }
}

#[derive(Debug, Clone)]
pub struct SingleHopBroadcastPacket<'a> {
    pub source_position: LongPositionVector,
    pub media_dependent: [u8; 4],
    pub inner_data: InnerData<'a>
}

impl SingleHopBroadcastPacket<'_> {
    fn into_owned(self) -> SingleHopBroadcastPacket<'static> {
        SingleHopBroadcastPacket {
            source_position: self.source_position,
            media_dependent: self.media_dependent,
            inner_data: self.inner_data.into_owned()
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DistributedCongestionControlData {
    pub local_channel_busy_ratio: f32,
    pub max_neighboring_channel_busy_ratio: f32,
    pub transmit_power_dbm: u8,
}

#[derive(Debug, Clone)]
pub struct BeaconPacket {
    pub source_position: LongPositionVector
}

#[derive(Debug, Clone)]
pub enum InnerData<'a> {
    BtpA {
        destination_port: u16,
        source_port: u16,
        data: alloc::borrow::Cow<'a, [u8]>
    },
    BtpB {
        destination_port: u16,
        destination_port_info: u16,
        data: alloc::borrow::Cow<'a, [u8]>
    },
    Ipv6(alloc::borrow::Cow<'a, [u8]>),
}

impl InnerData<'_> {
    fn into_owned(self) -> InnerData<'static> {
        match self {
            Self::BtpA { destination_port, source_port, data } => InnerData::BtpA {
                destination_port,
                source_port,
                data: alloc::borrow::Cow::Owned(data.into_owned())
            },
            Self::BtpB { destination_port, destination_port_info, data } => InnerData::BtpB {
                destination_port,
                destination_port_info,
                data: alloc::borrow::Cow::Owned(data.into_owned())
            },
            Self::Ipv6(data) => InnerData::Ipv6(alloc::borrow::Cow::Owned(data.into_owned()))
        }
    }
}

struct _CommonHeader {
    next_header: u8,
    header_type: u8,
    header_sub_type: u8,
    traffic_class: TrafficClass,
    is_mobile: bool,
    payload_length: u16,
    maximum_hop_limit: u8,
}

#[derive(Debug, Copy, Clone, serde::Serialize)]
pub struct TrafficClass {
    pub store_carry_forward: bool,
    pub channel_offload: bool,
    pub traffic_class_id: u8,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct LatLong {
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Debug, Clone)]
pub struct LongPositionVector {
    pub address: GnAddress,
    pub position: LatLong,
    pub acquisition_time: Time,
    pub accurate_position: bool,
    pub speed_ms: f32,
    pub heading_deg: f32,
}

#[derive(Debug, Clone)]
pub struct GnAddress {
    pub manually_configured: bool,
    pub traffic_participant_type: u8,
    pub mac_address: ieee80211::mac_parser::MACAddress
}

impl<'a> GeoNetworkingFrame<'a> {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4);
        let next_header = match self.data {
            PacketType::Unsecured(_) => 1,
            PacketType::Secured { .. } => 2
        };
        out.push(0b0001_0000 | next_header);
        out.push(0);

        if self.basic_header.lifetime <= core::time::Duration::from_millis(32000) {
            let lt_multiplier = self.basic_header.lifetime.as_millis().div_ceil(500);
            out.push((((lt_multiplier as u8) << 2) & 0xff) | 0b00);
        } else if self.basic_header.lifetime <= core::time::Duration::from_secs(64) {
            let lt_multiplier = self.basic_header.lifetime.as_secs().div_ceil(1);
            out.push((((lt_multiplier as u8) << 2) & 0xff) | 0b01);
        } else if self.basic_header.lifetime <= core::time::Duration::from_secs(640) {
            let lt_multiplier = self.basic_header.lifetime.as_secs().div_ceil(10);
            out.push((((lt_multiplier as u8) << 2) & 0xff) | 0b10);
        } else {
            let lt_multiplier = self.basic_header.lifetime.as_secs().div_ceil(100);
            out.push((((lt_multiplier as u8) << 2) & 0xff) | 0b11);
        }
        out.push(self.basic_header.remaining_hop_limit);

        match &self.data {
            PacketType::Unsecured(ch) => {
                ch.write(&mut out);
            },
            PacketType::Secured { .. } => {
                unimplemented!()
            }
        }

        out
    }

    pub fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        if data.len() < 4 {
            return Err("frame too short");
        }
        let version = data[0] >> 4;
        let next_header = data[0] & 0x0f;
        if version != 1 {
            return Err("unsupported GeoNetworking version");
        }

        let lt_base = match data[2] & 0b11 {
            0 => core::time::Duration::from_millis(500),
            1 => core::time::Duration::from_secs(1),
            2 => core::time::Duration::from_secs(10),
            3 => core::time::Duration::from_secs(100),
            _ => unreachable!()
        };
        let lt_multiplier = data[2] >> 2;
        let lifetime = lt_multiplier as u32 * lt_base;
        let remaining_hop_limit = data[3];

        let data = if next_header == 0 || next_header == 1 {
            PacketType::Unsecured(CommonHeader::parse(&data[4..])?)
        } else if next_header == 2 {
            let signed_data = match rasn::oer::decode::<rasn_its::ts103097::EtsiTs103097Data>(&data[4..]) {
                Ok(signed_data) => signed_data,
                Err(_) => {
                    return Err("invalid signed data encoding")
                }
            };
            if signed_data.protocol_version != 3 {
                return Err("unsupported signed data version")
            }
            match &signed_data.content {
                rasn_its::ieee1609dot2::Ieee1609Dot2Content::SignedData(signed_data_content) => {
                    PacketType::Secured(SignedPacket(*signed_data_content.to_owned()))
                },
                _ => return Err("unsupported signed data variant")
            }
        } else {
            return Err("invalid next header");
        };

        Ok(Self {
            basic_header: BasicHeader {
                lifetime,
                remaining_hop_limit
            },
            data,
        })
    }
}

impl SignedPacket {
    pub fn common_header(&self) -> Result<CommonHeader, &'static str> {
        let Some(inner_data) = &self.0.tbs_data.payload.data else {
            return Err("signed data value not present")
        };
        if inner_data.protocol_version != 3 {
            return Err("unsupported signed data version")
        }
        let rasn_its::ieee1609dot2::Ieee1609Dot2Content::UnsecuredData(inner_data) = &inner_data.content else {
            return Err("invalid signed data value")
        };
        Ok(CommonHeader::parse(&inner_data.0.as_ref())?)
    }
}

impl<'a> CommonHeader<'a> {
    fn write(&self, out: &mut Vec<u8>) {
        let (header_type, header_sub_type, inner_data) = match &self.data {
            PacketData::Beacon(_) => (1, 0, None),
            PacketData::GeoAnycast(i) => match &i.area {
                GeoArea::Circle { .. } => (3, 0, Some(&i.inner_data)),
                GeoArea::Rectangle { .. } => (3, 1, Some(&i.inner_data)),
                GeoArea::Ellipse { .. } => (3, 2, Some(&i.inner_data)),
            }
            PacketData::GeoBroadcast(i) => match &i.area {
                GeoArea::Circle { .. } => (4, 0, Some(&i.inner_data)),
                GeoArea::Rectangle { .. } => (4, 1, Some(&i.inner_data)),
                GeoArea::Ellipse { .. } => (4, 2, Some(&i.inner_data)),
            }
            PacketData::SingleHopBroadcast(i) => (5, 0, Some(&i.inner_data)),
            PacketData::MultiHopBroadcast(i) => (5, 1, Some(&i.inner_data)),
        };

        let common_header = _CommonHeader {
            next_header: inner_data.map(InnerData::next_header).unwrap_or(0),
            header_type,
            header_sub_type,
            traffic_class: self.traffic_class,
            is_mobile: self.is_mobile,
            payload_length: inner_data.map(InnerData::payload_length).unwrap_or(0),
            maximum_hop_limit: self.maximum_hop_limit,
        };
        common_header.write(out);

        match &self.data {
            PacketData::Beacon(pv) => {
                pv.source_position.write(out);
            },
            PacketData::SingleHopBroadcast(shb) => {
                shb.source_position.write(out);
                out.extend_from_slice(shb.media_dependent.as_ref());
            },
            PacketData::MultiHopBroadcast(mhb) => {
                out.extend_from_slice(&mhb.sequence.to_be_bytes());
                out.extend_from_slice(&[0, 0]);
                mhb.source_position.write(out);
            },
            _ => unimplemented!()
        }

        if let Some(inner_data) = inner_data {
            inner_data.write(out);
        }
    }

    fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        let common_header = _CommonHeader::parse(data)?;
        let extended_header = &data[8..];

        let packet_data = if common_header.header_type == 0 {
            return Err("header type ANY is invalid");
        } else if common_header.header_type == 1 {
            if common_header.header_sub_type == 0 {
                if extended_header.len() < 24 {
                    return Err("extended header too short");
                }
                PacketData::Beacon(BeaconPacket{
                    source_position: LongPositionVector::parse(&extended_header[0..24]),
                })
            } else {
                return Err("invalid BEACON sub-type");
            }
        } else if common_header.header_type == 3 || common_header.header_type == 4 {
            let a = u16::from_be_bytes([extended_header[36], extended_header[37]]);
            let b = u16::from_be_bytes([extended_header[38], extended_header[39]]);
            let angle = u16::from_be_bytes([extended_header[40], extended_header[41]]);
            let area = if common_header.header_sub_type == 0 {
                GeoArea::Circle {
                    radius: a,
                }
            } else if common_header.header_sub_type == 1 {
                GeoArea::Rectangle {
                    height: a,
                    width: b,
                    angle,
                }
            } else if common_header.header_sub_type == 2 {
                GeoArea::Ellipse {
                    a,
                    b,
                    angle,
                }
            } else {
                return Err("invalid GeoCast area type");
            };

            let packet = GeoCastPacket {
                source_position: LongPositionVector::parse(&extended_header[4..28]),
                sequence: u16::from_be_bytes([extended_header[0], extended_header[1]]),
                area_centre: LatLong {
                    latitude: i32::from_be_bytes([extended_header[28], extended_header[29], extended_header[30], extended_header[31]]) as f64 / 10_000_000.0,
                    longitude: i32::from_be_bytes([extended_header[32], extended_header[33], extended_header[34], extended_header[35]]) as f64 / 10_000_000.0,
                },
                area,
                inner_data: InnerData::parse(common_header.next_header, common_header.payload_length, &extended_header[44..])?,
            };

            if common_header.header_type == 3 {
                PacketData::GeoAnycast(packet)
            } else {
                PacketData::GeoBroadcast(packet)
            }
        } else if common_header.header_type == 5 {
            if common_header.header_sub_type == 0 {
                if extended_header.len() < 28 {
                    return Err("extended header too short");
                }
                PacketData::SingleHopBroadcast(SingleHopBroadcastPacket {
                    source_position: LongPositionVector::parse(&extended_header[0..24]),
                    media_dependent: [extended_header[24], extended_header[25], extended_header[26], extended_header[27]],
                    inner_data: InnerData::parse(common_header.next_header, common_header.payload_length, &extended_header[28..])?,
                })
            } else if common_header.header_sub_type == 1 {
                if extended_header.len() < 28 {
                    return Err("extended header too short");
                }
                PacketData::MultiHopBroadcast(MultipHopBroadcastPacket {
                    source_position: LongPositionVector::parse(&extended_header[4..28]),
                    sequence: u16::from_be_bytes([extended_header[0], extended_header[1]]),
                    inner_data: InnerData::parse(common_header.next_header, common_header.payload_length, &extended_header[28..])?,
                })
            } else {
                return Err("invalid TSB sub-type");
            }
        } else {
            return Err("unsupported header type");
        };

        Ok(Self {
            is_mobile: common_header.is_mobile,
            traffic_class: common_header.traffic_class,
            maximum_hop_limit: common_header.maximum_hop_limit,
            data: packet_data
        })
    }
}

impl TrafficClass {
    fn to_u8(&self) -> u8 {
        let mut val = self.traffic_class_id & 0b00111111;
        if self.store_carry_forward {
            val |= 0b10000000;
        }
        val
    }

    fn parse(val: u8) -> Self {
        let store_carry_forward = val & 0b10000000 != 0;
        let channel_offload = val & 0b01000000 != 0;
        let traffic_class_id = val & 0b00111111;
        Self {
            store_carry_forward,
            channel_offload,
            traffic_class_id
        }
    }
}

impl _CommonHeader {
    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.next_header << 4);
        out.push((self.header_sub_type & 0x0f) | (self.header_type << 4));
        out.push(self.traffic_class.to_u8());
        out.push(if self.is_mobile { 0b10000000 } else { 0 });
        out.extend_from_slice(&self.payload_length.to_be_bytes());
        out.push(self.maximum_hop_limit);
        out.push(0);
    }
    fn parse(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 8 {
            return Err("common header too short");
        }
        let next_header = data[0] >> 4;
        let header_type = data[1] >> 4;
        let header_sub_type = data[1] & 0x0f;
        let traffic_class = TrafficClass::parse(data[2]);
        let is_mobile = data[3] & 0b10000000 != 0;
        let payload_length = u16::from_be_bytes([data[4], data[5]]);
        let maximum_hop_limit = data[6];
        Ok(Self {
            next_header,
            header_type,
            header_sub_type,
            traffic_class,
            is_mobile,
            payload_length,
            maximum_hop_limit,
        })
    }
}

impl LongPositionVector {
    fn write(&self, out: &mut Vec<u8>) {
        self.address.write(out);
        out.extend_from_slice(&self.acquisition_time.0.to_be_bytes());
        out.extend_from_slice(&(((self.position.latitude * 10_000_000.0) as i32).to_be_bytes()));
        out.extend_from_slice(&(((self.position.longitude * 10_000_000.0) as i32).to_be_bytes()));
        let mut speed = ((self.speed_ms * 100.0) as i16).to_be_bytes();
        speed[0] &= 0x7f;
        if self.accurate_position {
            speed[0] |= 0b10000000;
        }
        out.extend_from_slice(&speed);
        out.extend_from_slice(&((self.heading_deg * 10.0) as u16).to_be_bytes());
    }
    fn parse(data: &[u8]) -> Self {
        let speed_sign = (data[20] & 0b0100_0000 >> 6) != 0;
        let speed_value = if speed_sign {
            i16::from_be_bytes([(data[20] & 0b0011_1111) | 0b1100_0000, data[21]])
        } else {
            i16::from_be_bytes([data[20] & 0b011_11111, data[21]])
        };
        Self {
            address: GnAddress::parse(&data[0..8]),
            position: LatLong {
                latitude: i32::from_be_bytes([data[12], data[13], data[14], data[15]]) as f64 / 10_000_000.0,
                longitude: i32::from_be_bytes([data[16], data[17], data[18], data[19]]) as f64 / 10_000_000.0,
            },
            acquisition_time: Time(u32::from_be_bytes([data[8], data[9], data[10], data[11]])),
            accurate_position: data[20] & 0b10000000 != 0,
            speed_ms: speed_value as f32 / 100.0,
            heading_deg: u16::from_be_bytes([data[22], data[23]]) as f32 / 10.0
        }
    }
}

impl GnAddress {
    fn write(&self, out: &mut Vec<u8>) {
        out.push(
            if self.manually_configured { 0b10000000 } else { 0 } |
                (self.traffic_participant_type & 0b11111) << 2
        );
        out.push(0);
        out.extend_from_slice(self.mac_address.as_slice());
    }
    fn parse(data: &[u8]) -> Self {
        Self {
            manually_configured: data[0] & 0b10000000 != 0,
            traffic_participant_type: data[0] >> 2 & 0b11111,
            mac_address: ieee80211::mac_parser::MACAddress([data[2], data[3], data[4], data[5], data[6], data[7]]),
        }
    }
}

impl<'a> InnerData<'a> {
    fn payload_length(&self) -> u16 {
        match self {
            Self::BtpA { data, .. } => 4 + data.len() as u16,
            Self::BtpB { data, .. } => 4 + data.len() as u16,
            Self::Ipv6(data) => data.len() as u16,
        }
    }

    fn next_header(&self) -> u8 {
        match self {
            Self::BtpA { .. } => 1,
            Self::BtpB { .. } => 2,
            Self::Ipv6(_) => 3,
        }
    }

    fn write(&self, out: &mut Vec<u8>) {

        match self {
            Self::BtpA { destination_port, source_port, data} => {
                out.extend_from_slice(&destination_port.to_be_bytes());
                out.extend_from_slice(&source_port.to_be_bytes());
                out.extend_from_slice(data.as_ref());
            }
            Self::BtpB { destination_port, destination_port_info, data } => {
                out.extend_from_slice(&destination_port.to_be_bytes());
                out.extend_from_slice(&destination_port_info.to_be_bytes());
                out.extend_from_slice(data.as_ref());
            }
            Self::Ipv6(data) => {
                out.extend_from_slice(&data.as_ref());
            }
        }
    }

    fn parse(next_header: u8, payload_length: u16, data: &'a [u8]) -> Result<Self, &'static str> {
        if payload_length as usize > data.len() {
            return Err("not enough data for payload")
        }
        match next_header {
            1 => {
                if data.len() < 4 {
                    return Err("not enough data for payload");
                }
                Ok(Self::BtpA {
                    destination_port: u16::from_be_bytes([data[0], data[1]]),
                    source_port: u16::from_be_bytes([data[2], data[3]]),
                    data: alloc::borrow::Cow::Borrowed(&data[4..payload_length as usize]),
                })
            },
            2 => {
                if data.len() < 4 {
                    return Err("not enough data for payload");
                }
                Ok(Self::BtpB {
                    destination_port: u16::from_be_bytes([data[0], data[1]]),
                    destination_port_info: u16::from_be_bytes([data[2], data[3]]),
                    data: alloc::borrow::Cow::Borrowed(&data[4..payload_length as usize]),
                })
            }
            3 => Ok(Self::Ipv6(alloc::borrow::Cow::Borrowed(&data[0..payload_length as usize]))),
            _ => Err("invalid payload next header")
        }
    }
}

impl DistributedCongestionControlData {
    pub fn parse(data: &[u8; 4]) -> Self {
        Self {
            local_channel_busy_ratio: data[0] as f32 / 255.0,
            max_neighboring_channel_busy_ratio: data[1] as f32 / 255.0,
            transmit_power_dbm: data[2] >> 3
        }
    }
}