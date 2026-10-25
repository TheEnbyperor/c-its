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
    revoked_certs: std::path::PathBuf,

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
    let revoked_certs = std::fs::read_to_string(&args.revoked_certs).expect("failed to read revoked certificates list");

    let now = chrono::Utc::now();

    let mut crl_entries = vec![];
    for line in revoked_certs.lines() {
        let id8 = hex::decode(line).expect("Invalid HashID8");
        let id8: [u8; 8] = id8.try_into().expect("Invalid HashID8, not 8 bytes long");
        crl_entries.push(c_its::asn::etsi_ts102941_trust_lists::CrlEntry(
            rasn_its::ieee1609dot2::base_types::HashedId8(id8.into())
        ))
    }

    let crl_content = c_its::asn::etsi_ts102941_trust_lists::ToBeSignedCrl::new(
        c_its::asn::etsi_ts102941_base_types::Version(1.into()),
        c_its::security::certs::utc_to_time32(&now),
        c_its::security::certs::utc_to_time32(&(now + chrono::TimeDelta::days(7))),
        crl_entries.into()
    );

    let crl = pki_certs::sign_message::<c_its::asn::etsi_ts102941_trust_lists::ToBeSignedCrl>(
        &rasn::oer::encode(&c_its::asn::etsi_ts_102941_messages_ca::EtsiTs102941Data {
            version: c_its::asn::etsi_ts102941_base_types::Version(1.into()),
            content: c_its::asn::etsi_ts_102941_messages_ca::EtsiTs102941DataContent::certificateRevocationList(crl_content),
        }).unwrap(),
        &now,
        &root_key,
        &root_cert
    );

    let id8 = hex::encode_upper(root_cert.id8().unwrap());
    println!("Generated CRL for root with ID8 {}", id8);

    let crl_bytes = rasn::oer::encode(&crl).unwrap();
    let resp = s3_client.put_object()
        .bucket(args.bucket_name)
        .key(format!("{}getcrl/{}", args.bucket_path_prefix, id8))
        .content_type("application/x-its-crl")
        .body(aws_sdk_s3::primitives::ByteStream::from(crl_bytes))
        .send().await.unwrap();
    println!("Upload success. Version: {:?}", resp.version_id().unwrap());
}
