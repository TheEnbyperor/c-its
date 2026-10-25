use clap::Parser;

mod pki_certs;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    root_cert: std::path::PathBuf,
    #[arg(long)]
    root_key: std::path::PathBuf,

    #[arg(long)]
    aa_access_point: String,
    #[arg(long)]
    aa_certs: Option<Vec<std::path::PathBuf>>,
    #[arg(long)]
    ea_certs: Option<Vec<std::path::PathBuf>>,

    #[arg(long)]
    bucket_name: String,
    #[arg(long)]
    bucket_path_prefix: String
}

#[::tokio::main]
async fn main() {
    let args = Args::parse();
    let aws_config = aws_config::from_env()
        .app_name(aws_config::AppName::new("C-ITS_PKI_Tools").unwrap())
        .load().await;
    let s3_client = aws_sdk_s3::Client::new(&aws_config);

    let root_cert = c_its::security::certs::Certificate::parse(&std::fs::read(&args.root_cert).unwrap()).unwrap();
    let root_key = c_its::security::crypto::PrivateKey::<c_its::security::std_crypto::StdCrypto>::from_bytes_pem(&std::fs::read(&args.root_key).unwrap()).unwrap();

    let id8 = hex::encode_upper(root_cert.id8().unwrap_or_default());
    let now = chrono::Utc::now();
    let aa_access_point = c_its::asn::etsi_ts102941_trust_lists::Url(
        rasn::types::Ia5String::try_from(args.aa_access_point).unwrap(),
    );

    let full_ctl_key = format!("{}getctl/{}", args.bucket_path_prefix, id8);
    let previous_ctl = match s3_client
        .get_object()
        .bucket(&args.bucket_name)
        .key(&full_ctl_key)
        .send()
        .await
    {
        Ok(response) => {
            let bytes = response
                .body
                .collect()
                .await
                .expect("Failed to read previous CTL")
                .into_bytes();
            Some(bytes)
        }
        Err(err) => {
            if err
                .as_service_error()
                .map(|e| e.is_no_such_key())
                .unwrap_or(false)
            {
                None
            } else {
                panic!("Failed to fetch previous CTL: {err}");
            }
        }
    };

    let mut new_entries = Vec::new();
    for cert_path in args.aa_certs.unwrap_or_default() {
        let cert = c_its::security::certs::Certificate::parse(&std::fs::read(&cert_path).unwrap())
            .expect("Failed to parse AA certificate");
        new_entries.push(c_its::asn::etsi_ts102941_trust_lists::CtlEntry::aa(
                c_its::asn::etsi_ts102941_trust_lists::AaEntry::new(cert.to_cert(), aa_access_point.clone())
            )
        );
    }
    for cert_path in args.ea_certs.unwrap_or_default() {
        let cert = c_its::security::certs::Certificate::parse(&std::fs::read(&cert_path).unwrap())
            .expect("Failed to parse EA certificate");
        new_entries.push(c_its::asn::etsi_ts102941_trust_lists::CtlEntry::ea(
                c_its::asn::etsi_ts102941_trust_lists::EaEntry::new(cert.to_cert(), aa_access_point.clone(), None)
            )
        );
    }

    let (next_sequence, old_entries) = match previous_ctl.as_deref() {
        Some(bytes) => {
            let prev_ctl: rasn_its::ts103097::EtsiTs103097DataSigned<c_its::asn::etsi_ts_102941_messages_ca::RcaCertificateTrustListMessage> = rasn::oer::decode(&bytes).unwrap();
            assert_eq!(prev_ctl.protocol_version, 3);
            let rasn_its::ieee1609dot2::Ieee1609Dot2Content::SignedData(ref ctl) = prev_ctl.content else {
                unreachable!();
            };
            let Some(ref prev_ctl_inner_data) = ctl.tbs_data.payload.data else {
                panic!("Previous CTL does not contain any data");
            };
            assert_eq!(prev_ctl_inner_data.protocol_version, 3);
            let rasn_its::ieee1609dot2::Ieee1609Dot2Content::UnsecuredData(ref ctl_inner_data) = prev_ctl_inner_data.content else {
                panic!("Previous CTL does not contain any data");
            };
            let prev_ctl_inner: c_its::asn::etsi_ts_102941_messages_ca::EtsiTs102941Data = rasn::oer::decode(&ctl_inner_data.0).unwrap();
            let c_its::asn::etsi_ts_102941_messages_ca::EtsiTs102941DataContent::certificateTrustListRca(ref previous) = prev_ctl_inner.content else {
                panic!("Previous CTL data does not a CTL element");
            };

            assert!(previous.0.is_full_ctl, "Object at {} is not a full CTL", full_ctl_key);
            (
                (previous.0.ctl_sequence + 1) & 0xff,
                previous.0.ctl_commands.iter().map(|command| match command {
                    c_its::asn::etsi_ts102941_trust_lists::CtlCommand::add(entry) => entry.clone(),
                    c_its::asn::etsi_ts102941_trust_lists::CtlCommand::delete(_) => panic!("Full CTL contains a delete command"),
                    _ => panic!("Unknown command in previous CTL"),
                }).collect::<Vec<_>>(),
            )
        }
        None => (0, Vec::new()),
    };

    let full_commands = new_entries.iter().cloned()
        .map(c_its::asn::etsi_ts102941_trust_lists::CtlCommand::add).collect::<Vec<_>>();
    let next_update = c_its::security::certs::utc_to_time32(&(now + chrono::TimeDelta::days(7)));
    let full_ctl_content = c_its::asn::etsi_ts102941_trust_lists::ToBeSignedRcaCtl(
        c_its::asn::etsi_ts102941_trust_lists::CtlFormat::new(
            c_its::asn::etsi_ts102941_base_types::Version(1.into()),
            next_update.clone(),
            true,
            next_sequence,
            full_commands.into()
        )
    );
    let full_ctl = pki_certs::sign_message::<c_its::asn::etsi_ts102941_trust_lists::ToBeSignedCrl>(
        &rasn::oer::encode(&c_its::asn::etsi_ts_102941_messages_ca::EtsiTs102941Data {
            version: c_its::asn::etsi_ts102941_base_types::Version(1.into()),
            content: c_its::asn::etsi_ts_102941_messages_ca::EtsiTs102941DataContent::certificateTrustListRca(full_ctl_content),
        }).unwrap(),
        &now,
        &root_key,
        &root_cert,
    );
    println!("Generated full CTL for root with ID8 {}, sequence {}", id8, next_sequence);

    let delta_ctl = previous_ctl.as_ref().map(|_| {
        let mut delta_commands = Vec::new();
        for new_entry in &new_entries {
            let new_id = entry_id8(&new_entry);
            let old_entry = old_entries.iter().find(|entry| entry_id8(entry) == new_id);
            match old_entry {
                None => {
                    delta_commands.push(c_its::asn::etsi_ts102941_trust_lists::CtlCommand::add(new_entry.clone()));
                },
                Some(old_entry) if rasn::oer::encode(old_entry).unwrap() != rasn::oer::encode(new_entry).unwrap() => {
                    delta_commands.push(c_its::asn::etsi_ts102941_trust_lists::CtlCommand::add(new_entry.clone()));
                }
                Some(_) => {}
            }
        }
        for old_entry in old_entries {
            let old_id = entry_id8(&old_entry);
            if !new_entries.iter().any(|entry| entry_id8(entry) == old_id) {
                delta_commands.push(c_its::asn::etsi_ts102941_trust_lists::CtlCommand::delete(
                    c_its::asn::etsi_ts102941_trust_lists::CtlDelete::cert(
                        rasn_its::ieee1609dot2::base_types::HashedId8(old_id.into())
                    )
                ));
            }
        }
        println!("Delta CTL sequence {} contains {} command(s)", next_sequence, delta_commands.len());
        let delta_ctl_content = c_its::asn::etsi_ts102941_trust_lists::ToBeSignedRcaCtl(
            c_its::asn::etsi_ts102941_trust_lists::CtlFormat::new(
                c_its::asn::etsi_ts102941_base_types::Version(1.into()),
                next_update.clone(),
                false,
                next_sequence,
                delta_commands.into()
            )
        );
        pki_certs::sign_message::<c_its::asn::etsi_ts102941_trust_lists::ToBeSignedCrl>(
            &rasn::oer::encode(&c_its::asn::etsi_ts_102941_messages_ca::EtsiTs102941Data {
                version: c_its::asn::etsi_ts102941_base_types::Version(1.into()),
                content: c_its::asn::etsi_ts_102941_messages_ca::EtsiTs102941DataContent::certificateTrustListRca(delta_ctl_content),
            }).unwrap(),
            &now,
            &root_key,
            &root_cert,
        )
    });

    if let Some(delta_ctl) = delta_ctl {
        let delta_ctl_bytes = rasn::oer::encode(&delta_ctl).unwrap();
        let delta_key = format!("{}getctl/{}/{}", args.bucket_path_prefix, id8, next_sequence);
        let resp = s3_client.put_object()
            .bucket(&args.bucket_name)
            .key(delta_key)
            .content_type("application/x-its-ctl")
            .body(aws_sdk_s3::primitives::ByteStream::from(delta_ctl_bytes))
            .send().await.unwrap();

        println!("Uploaded delta CTL {}. Version: {}", next_sequence, resp.version_id().unwrap());
    }

    let full_ctl_bytes = rasn::oer::encode(&full_ctl).unwrap();
    let resp = s3_client.put_object()
        .bucket(&args.bucket_name)
        .key(full_ctl_key)
        .content_type("application/x-its-ctl")
        .body(aws_sdk_s3::primitives::ByteStream::from(full_ctl_bytes))
        .send().await.unwrap();
    println!("Uploaded full CTL. Version: {}", resp.version_id().unwrap());
}

fn entry_id8(entry: &c_its::asn::etsi_ts102941_trust_lists::CtlEntry) -> [u8; 8] {
    match entry {
        c_its::asn::etsi_ts102941_trust_lists::CtlEntry::aa(entry) => {
            c_its::security::certs::Certificate::new(&entry.aa_certificate).id8().unwrap()
        }
        c_its::asn::etsi_ts102941_trust_lists::CtlEntry::ea(entry) => {
            c_its::security::certs::Certificate::new(&entry.ea_certificate).id8().unwrap()
        }
        _ => panic!("Unexpected entry type in RCA CTL"),
    }
}