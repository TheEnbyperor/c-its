use clap::Parser;

mod pki_certs;

#[derive(Copy, Clone, Debug, clap::ValueEnum, PartialEq, Eq)]
enum CAMPermission {
    Basic,
    CenDsrcTollingZone,
    PublicTransport,
    SpecialTransport,
    DangerousGoods,
    Roadworks,
    Rescue,
    Emergency,
    SafetyCar,
    ClosedLanes,
    RequestRightOfWay,
    RequestFreeCrossing,
    NoPassing,
    NoPassingForTrucks,
    SpeedLimit,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    aa_cert: std::path::PathBuf,
    #[arg(long)]
    aa_key: std::path::PathBuf,

    #[arg(long)]
    cam_perms: Option<Vec<CAMPermission>>
}


fn main() {
    let args = Args::parse();

    let aa_cert = c_its::security::certs::Certificate::parse(&std::fs::read(&args.aa_cert).unwrap()).unwrap();
    let aa_key = c_its::security::crypto::PrivateKey::<c_its::security::std_crypto::StdCrypto>::from_bytes_pem(&std::fs::read(&args.aa_key).unwrap()).unwrap();

    let cert_info = pki_certs::CertInfo::collect_info("authorization ticket", false);
    let valid_from = chrono::Utc::now();
    let verification_private_key = cert_info.key_alg.generate_private_key();

    std::fs::create_dir_all("./pki-store/").unwrap();

    let mut app_perms = vec![];

    if let Some(cam_perms) = args.cam_perms {
        if cam_perms.contains(&CAMPermission::Basic) {
            let mut cam = c_its::security::perms::CAMPermissions::default();

            cam.cen_dsrc_tolling_zone = cam_perms.contains(&CAMPermission::CenDsrcTollingZone);
            cam.public_transport = cam_perms.contains(&CAMPermission::PublicTransport);
            cam.special_transport = cam_perms.contains(&CAMPermission::SpecialTransport);
            cam.dangerous_goods = cam_perms.contains(&CAMPermission::DangerousGoods);
            cam.roadworks = cam_perms.contains(&CAMPermission::Roadworks);
            cam.rescue = cam_perms.contains(&CAMPermission::Rescue);
            cam.emergency = cam_perms.contains(&CAMPermission::Emergency);
            cam.safety_car = cam_perms.contains(&CAMPermission::SafetyCar);
            cam.closed_lanes = cam_perms.contains(&CAMPermission::ClosedLanes);
            cam.request_right_of_way = cam_perms.contains(&CAMPermission::RequestRightOfWay);
            cam.request_free_crossing = cam_perms.contains(&CAMPermission::RequestFreeCrossing);
            cam.no_passing = cam_perms.contains(&CAMPermission::NoPassing);
            cam.no_passing_for_trucks = cam_perms.contains(&CAMPermission::NoPassingForTrucks);
            cam.speed_limit = cam_perms.contains(&CAMPermission::SpeedLimit);

            app_perms.push(rasn_its::ieee1609dot2::base_types::PsidSsp {
                psid: rasn_its::ieee1609dot2::base_types::Psid(c_its::security::perms::PSID_CAM.clone()),
                ssp: Some(rasn_its::ieee1609dot2::base_types::ServiceSpecificPermissions::BitmapSsp(
                    cam.as_bitmap()
                ))
            });
        }
    }

    let tbs_cert = rasn_its::ieee1609dot2::ToBeSignedCertificate::builder()
        .id(rasn_its::ieee1609dot2::CertificateId::None(()))
        .craca_id(rasn_its::ieee1609dot2::base_types::HashedId3(
            rasn::types::FixedOctetString::new([0, 0, 0]),
        ))
        .crl_series(rasn_its::ieee1609dot2::base_types::CrlSeries(0))
        .validity_period(rasn_its::ieee1609dot2::base_types::ValidityPeriod {
            start: c_its::security::certs::utc_to_time32(&valid_from),
            duration: rasn_its::ieee1609dot2::base_types::Duration::Years(cert_info.validity_duration_years),
        })
        .app_permissions(rasn_its::ieee1609dot2::base_types::SequenceOfPsidSsp(app_perms.into()))
        .verify_key_indicator(rasn_its::ieee1609dot2::VerificationKeyIndicator::VerificationKey(
            verification_private_key.public_key().encode(),
        ))
        .build()
        .unwrap();

    let cert = pki_certs::sign_cert(tbs_cert, &aa_key, Some(&aa_cert));
    let cert_report = cert.report::<c_its::security::std_crypto::StdCrypto>().unwrap();
    let id8 = hex::encode_upper(cert_report.id8());
    println!("Generated authorization ticket certificate with ID8 {}", id8);

    std::fs::write(format!("./pki-store/at-{}.oer", id8), cert.to_bytes()).unwrap();
    std::fs::write(format!("./pki-store/at-{}.key", id8), verification_private_key.as_bytes_pem()).unwrap();
}
