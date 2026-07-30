use std::str::FromStr;

mod data_structures;

use c_its::geo_networking;
use c_its::llc;

use pcap_parser::traits::PcapReaderIterator;

const LINK_TYPE_802_11: pcap_parser::Linktype = pcap_parser::Linktype(105);

fn handle_802_11_frame(
    data: &[u8],
    timestamp: chrono::DateTime<chrono::Utc>,
    store: &mut c_its::security::SecurityStore,
) {
    let frame = match ieee80211::GenericFrame::new(data, false) {
        Ok(frame) => frame,
        Err(err) => {
            log::warn!("Unable to parse 802.11 frame: {}", err);
            return;
        }
    };
    let Some(data_frame) = frame.parse_to_typed::<ieee80211::data_frame::DataFrame>() else {
        log::debug!("Non-data frame encountered");
        return;
    };
    let data_frame = match data_frame {
        Ok(data_frame) => data_frame,
        Err(err) => {
            log::warn!("Failed to parse data frame: {}", err);
            return;
        }
    };
    let Some(source_address) = data_frame.header.source_address() else {
        log::debug!("Frame without source address encountered");
        return;
    };
    let Some(bssid) = data_frame.header.bssid() else {
        log::debug!("Frame without BSSID encountered");
        return;
    };
    if bssid != &c_its::WILDCARD_MAC_ADDRESS {
        log::debug!("Not a 802.11p broadcast frame");
        return;
    }
    match data_frame.header.subtype {
        ieee80211::common::DataFrameSubtype::Data
        | ieee80211::common::DataFrameSubtype::QoSData => {}
        o => {
            log::debug!("Not a data frame: {:?}", o);
            return;
        }
    }
    let Some(ieee80211::data_frame::PotentiallyWrappedPayload::Unwrapped(data)) =
        data_frame.potentially_wrapped_payload(None)
    else {
        log::warn!("Failed to read frame data, mistakenly encrypted?");
        return;
    };
    let ieee80211::data_frame::DataFrameReadPayload::Single(data) = data else {
        log::warn!("A-MSDU frames not supported");
        return;
    };
    let llc_pdu = match llc::LinkLayerControlPdu::parse(data) {
        Ok(llc_pdu) => llc_pdu,
        Err(err) => {
            log::warn!("Failed to parse LLC PDU: {}", err);
            return;
        }
    };
    match &llc_pdu.control {
        llc::ControlField::Unnumbered {
            modifier,
            poll_final,
        } if *modifier == 0 && *poll_final == llc::PollFinal::Command => {}
        o => {
            log::warn!("Expected LLC unnumbered data, got: {:?}", o);
            return;
        }
    }
    if llc_pdu.dsap_address != 0xAA || llc_pdu.ssap_address != 0xAA {
        log::warn!(
            "Expected LLC SNAP, got src {:02X} dst {:02X}",
            llc_pdu.ssap_address,
            llc_pdu.dsap_address
        );
        return;
    }
    let snap_pdu = match llc::SnapPdu::parse(llc_pdu.data.as_ref()) {
        Ok(snap_pdu) => snap_pdu,
        Err(err) => {
            log::warn!("Failed to parse SNAP PDU: {}", err);
            return;
        }
    };
    if snap_pdu.protocol != llc::SnapProtocol::EtherType(c_its::GEO_NETWORKING_ETHERTYPE) {
        log::warn!("Unexpected EtherType, got {:02X?}", snap_pdu.protocol);
    }
    let geo_networking_frame =
        match geo_networking::GeoNetworkingFrame::parse(snap_pdu.data.as_ref()) {
            Ok(geo_networking_frame) => geo_networking_frame,
            Err(err) => {
                log::warn!("Failed to parse GeoNetworking frame: {}", err);
                return;
            }
        };
    let (frame_data, security_report) = match &geo_networking_frame.data {
        geo_networking::PacketType::Unsecured(ch) => (std::borrow::Cow::Borrowed(ch), None),
        geo_networking::PacketType::Secured(sh) => {
            let security_report = match sh.security_report(store, timestamp) {
                Ok(sr) => sr,
                Err(err) => {
                    log::warn!(
                        "Failed to generate security report for GeoNetworking frame: {}",
                        err
                    );
                    return;
                }
            };
            let ch = match sh.common_header() {
                Ok(ch) => ch,
                Err(err) => {
                    log::warn!("Failed to parse GeoNetworking frame: {}", err);
                    return;
                }
            };
            (std::borrow::Cow::Owned(ch), Some(security_report))
        }
    };

    let frame_inner_data = match &frame_data.data {
        geo_networking::PacketData::GeoAnycast(p) => Some(&p.inner_data),
        geo_networking::PacketData::GeoBroadcast(p) => Some(&p.inner_data),
        geo_networking::PacketData::MultiHopBroadcast(p) => Some(&p.inner_data),
        geo_networking::PacketData::SingleHopBroadcast(p) => Some(&p.inner_data),
        geo_networking::PacketData::Beacon(_) => None,
    };

    let frame_out = data_structures::ITSFrame {
        wifi_source_address: *source_address,
        timestamp,
        geo_networking: data_structures::GeoNetworkingFrame {
            lifetime_millis: geo_networking_frame.basic_header.lifetime.as_millis(),
            remaining_hop_limit: geo_networking_frame.basic_header.remaining_hop_limit,
            maximum_hop_limit: frame_data.maximum_hop_limit,
            is_mobile: frame_data.is_mobile,
            traffic_class: frame_data.traffic_class,
            header: match &frame_data.data {
                geo_networking::PacketData::GeoAnycast(p) => {
                    data_structures::PacketHeader::GeoAnycast {
                        source_position: (&p.source_position).into(),
                        sequence: p.sequence,
                        area_centre: p.area_centre,
                        area: p.area,
                    }
                }
                geo_networking::PacketData::GeoBroadcast(p) => {
                    data_structures::PacketHeader::GeoBroadcast {
                        source_position: (&p.source_position).into(),
                        sequence: p.sequence,
                        area_centre: p.area_centre,
                        area: p.area,
                    }
                }
                geo_networking::PacketData::MultiHopBroadcast(p) => {
                    data_structures::PacketHeader::MultiHopBroadcast {
                        source_position: (&p.source_position).into(),
                        sequence: p.sequence,
                    }
                }
                geo_networking::PacketData::SingleHopBroadcast(p) => {
                    data_structures::PacketHeader::SingleHopBroadcast {
                        source_position: (&p.source_position).into(),
                        dcc: geo_networking::DistributedCongestionControlData::parse(
                            &p.media_dependent,
                        ),
                    }
                }
                geo_networking::PacketData::Beacon(p) => data_structures::PacketHeader::Beacon {
                    source_position: (&p.source_position).into(),
                },
            },
            data: match frame_inner_data {
                Some(d) => Some(match d {
                    geo_networking::InnerData::BtpA {
                        source_port,
                        destination_port,
                        data,
                    } => data_structures::PacketData::BtpA {
                        source_port: *source_port,
                        destination_port: *destination_port,
                        data: data.as_ref(),
                    },
                    geo_networking::InnerData::BtpB {
                        destination_port,
                        destination_port_info,
                        data,
                    } => data_structures::PacketData::BtpB {
                        destination_port: *destination_port,
                        destination_port_info: *destination_port_info,
                        data: build_inner_data(
                            *destination_port,
                            data.as_ref(),
                            security_report.as_ref(),
                        ),
                    },
                    geo_networking::InnerData::Ipv6(data) => {
                        data_structures::PacketData::Ipv6(data.as_ref())
                    }
                }),
                None => None,
            },
            security: security_report,
        },
    };
    println!("{}", serde_json::to_string(&frame_out).unwrap());
}

fn build_inner_data<'a>(
    port: u16,
    data: &'a [u8],
    security_report: Option<&c_its::security::SecurityReport>,
) -> data_structures::InnerData<'a> {
    if port == 2001 {
        match rasn::uper::decode::<c_its::asn::cam_pdu_descriptions::CAM>(data) {
            Ok(cam) => data_structures::InnerData::CAM {
                data: serde_json::from_str(&rasn::jer::encode(&cam).unwrap()).unwrap(),
                security_authorized: security_report
                    .map(|r| c_its::security::perms::cam_authorized(&cam, r))
                    .unwrap_or(false),
            },
            Err(_) => data_structures::InnerData::Raw { data },
        }
    } else if port == 2002 {
        match rasn::uper::decode::<c_its::asn::denm_pdu_description::DENM>(data) {
            Ok(cam) => data_structures::InnerData::DENM {
                data: serde_json::from_str(&rasn::jer::encode(&cam).unwrap()).unwrap(),
            },
            Err(_) => data_structures::InnerData::Raw { data },
        }
    } else if port == 2003 {
        match rasn::uper::decode::<c_its::asn::mapem_pdu_descriptions::MAPEM>(data) {
            Ok(cam) => data_structures::InnerData::MAPEM {
                data: serde_json::from_str(&rasn::jer::encode(&cam).unwrap()).unwrap(),
            },
            Err(_) => data_structures::InnerData::Raw { data },
        }
    } else if port == 2004 {
        match rasn::uper::decode::<c_its::asn::spatem_pdu_descriptions::SPATEM>(data) {
            Ok(cam) => data_structures::InnerData::SPATEM {
                data: serde_json::from_str(&rasn::jer::encode(&cam).unwrap()).unwrap(),
            },
            Err(_) => data_structures::InnerData::Raw { data },
        }
    } else if port == 2006 {
        match rasn::uper::decode::<c_its::asn::ivim_pdu_descriptions::IVIM>(data) {
            Ok(cam) => data_structures::InnerData::IVIM {
                data: serde_json::from_str(&rasn::jer::encode(&cam).unwrap()).unwrap(),
            },
            Err(_) => data_structures::InnerData::Raw { data },
        }
    } else {
        data_structures::InnerData::Raw { data }
    }
}

fn main() {
    pretty_env_logger::init();

    let args = std::env::args().collect::<Vec<String>>();
    if args.len() != 2 {
        log::error!("Invalid number of arguments");
        return;
    }
    let pcap_file = std::fs::File::open(&args[1]).expect("Could not open PCAP file");
    let mut pcap_reader =
        pcap_parser::LegacyPcapReader::new(65536, pcap_file).expect("Unable to parse PCAP header");
    let mut pcap_header = None;

    let mut security_store = c_its::security::SecurityStore::new();

    let ctl_data_dir = std::path::PathBuf::from_str("./ctl").unwrap();
    for ctl_entry in ctl_data_dir.read_dir().unwrap() {
        let ctl_entry = ctl_entry.unwrap();
        if ctl_entry
            .file_name()
            .as_encoded_bytes()
            .starts_with(b"root-")
            && ctl_entry.file_name().as_encoded_bytes().ends_with(b".oer")
        {
            let root_ca_bytes =
                std::fs::read(&ctl_entry.path()).expect("Unable to read root CA file");
            let root_ca = c_its::security::certs::Certificate::parse(&root_ca_bytes).unwrap();
            security_store.add_root_ca(root_ca).unwrap();
        }
        if ctl_entry
            .file_name()
            .as_encoded_bytes()
            .starts_with(b"crl-")
            && ctl_entry.file_name().as_encoded_bytes().ends_with(b".oer")
        {
            let ctl_entry_name = ctl_entry.file_name().into_string().unwrap();
            if let Some(id8_str) = ctl_entry_name.split('-').skip(1).next() {
                let id8: [u8; 8] = hex::decode(id8_str).unwrap().try_into().unwrap();
                let crl_bytes = std::fs::read(&ctl_entry.path()).expect("Unable to read CRL file");
                let crl = c_its::security::certs::CRL::parse(&crl_bytes).unwrap();
                security_store.add_crl(id8, crl);
            }
        }
        if ctl_entry.file_name().as_encoded_bytes().starts_with(b"aa-")
            && ctl_entry.file_name().as_encoded_bytes().ends_with(b".oer")
        {
            let root_ca_bytes =
                std::fs::read(&ctl_entry.path()).expect("Unable to read AA cert file");
            let root_ca = c_its::security::certs::Certificate::parse(&root_ca_bytes).unwrap();
            security_store.insert_cert(root_ca).unwrap();
        }
    }

    loop {
        match pcap_reader.next() {
            Ok((offset, block)) => {
                match block {
                    pcap_parser::PcapBlockOwned::LegacyHeader(hdr) => {
                        if hdr.version_major != 2 {
                            log::error!("Invalid PCAP header version: {}", hdr.version_major);
                            return;
                        }
                        if hdr.network != LINK_TYPE_802_11 {
                            log::error!("Unsupported network link type: {}", hdr.network);
                            return;
                        }
                        if pcap_header.replace(hdr).is_some() {
                            log::error!("Duplicated PCAP header");
                            return;
                        }
                    }
                    pcap_parser::PcapBlockOwned::Legacy(b) => {
                        let Some(pcap_header) = &pcap_header else {
                            log::error!("Missing PCAP header");
                            return;
                        };
                        let ts = if pcap_header.is_nanosecond_precision() {
                            chrono::DateTime::<chrono::Utc>::from_timestamp(
                                b.ts_sec as i64,
                                b.ts_usec,
                            )
                            .unwrap()
                        } else {
                            chrono::DateTime::<chrono::Utc>::from_timestamp(
                                b.ts_sec as i64,
                                (b.ts_usec % 1000) * 1000000,
                            )
                            .unwrap()
                        };
                        handle_802_11_frame(&b.data, ts, &mut security_store);
                    }
                    pcap_parser::PcapBlockOwned::NG(_) => unreachable!(),
                }
                pcap_reader.consume(offset);
            }
            Err(pcap_parser::PcapError::Eof) => break,
            Err(pcap_parser::PcapError::Incomplete(_)) => {
                pcap_reader.refill().unwrap();
            }
            Err(e) => {
                log::error!("error while reading PCAP: {:?}", e);
                return;
            }
        }
    }
}
