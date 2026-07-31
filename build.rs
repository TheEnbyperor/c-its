use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR")?);

    rasn_compiler::Compiler::<rasn_compiler::prelude::RasnBackend, _>::new_with_config(
        rasn_compiler::prelude::RasnConfig {
            generate_from_impls: true,
            no_std_compliant_bindings: true,
            ..Default::default()
        },
    )
    .add_asn_sources_by_path(
        (&[
            std::path::PathBuf::from("asn1/ETSI-ITS-CDD.asn"),
            std::path::PathBuf::from("asn1/CAM-PDU-Descriptions.asn"),
            std::path::PathBuf::from("asn1/DENM-PDU-Description.asn"),
        ])
            .iter(),
    )
    .set_output_mode(rasn_compiler::OutputMode::SingleFile(
        out_path.join("cam_denm.rs"),
    ))
    .compile()?;

    rasn_compiler::Compiler::<rasn_compiler::prelude::RasnBackend, _>::new_with_config(
        rasn_compiler::prelude::RasnConfig {
            generate_from_impls: true,
            no_std_compliant_bindings: true,
            ..Default::default()
        },
    )
    .add_asn_sources_by_path(
        (&[
            std::path::PathBuf::from("asn1/MAPEM-PDU-Descriptions.asn"),
            std::path::PathBuf::from("asn1/DSRC.asn"),
        ])
            .iter(),
    )
    .set_output_mode(rasn_compiler::OutputMode::SingleFile(
        out_path.join("mapem.rs"),
    ))
    .compile()?;

    rasn_compiler::Compiler::<rasn_compiler::prelude::RasnBackend, _>::new_with_config(
        rasn_compiler::prelude::RasnConfig {
            generate_from_impls: true,
            no_std_compliant_bindings: true,
            ..Default::default()
        },
    )
    .add_asn_sources_by_path(
        (&[
            std::path::PathBuf::from("asn1/ETSI_ITS_DSRC_AddGrpC.asn"),
        ])
            .iter(),
    )
    .set_output_mode(rasn_compiler::OutputMode::SingleFile(
        out_path.join("dsrc_reg.rs"),
    ))
    .compile()?;

    rasn_compiler::Compiler::<rasn_compiler::prelude::RasnBackend, _>::new_with_config(
        rasn_compiler::prelude::RasnConfig {
            generate_from_impls: true,
            no_std_compliant_bindings: true,
            ..Default::default()
        },
    )
    .add_asn_sources_by_path(
        (&[std::path::PathBuf::from("asn1/SPATEM-PDU-Descriptions.asn")]).iter(),
    )
    .set_output_mode(rasn_compiler::OutputMode::SingleFile(
        out_path.join("spatem.rs"),
    ))
    .compile()?;

    rasn_compiler::Compiler::<rasn_compiler::prelude::RasnBackend, _>::new_with_config(
        rasn_compiler::prelude::RasnConfig {
            generate_from_impls: true,
            no_std_compliant_bindings: true,
            ..Default::default()
        },
    )
    .add_asn_sources_by_path(
        (&[
            std::path::PathBuf::from("asn1/SREM-PDU-Descriptions.asn"),
            std::path::PathBuf::from("asn1/SSEM-PDU-Descriptions.asn")
        ]).iter(),
    )
    .set_output_mode(rasn_compiler::OutputMode::SingleFile(
        out_path.join("tlc.rs"),
    ))
    .compile()?;

    rasn_compiler::Compiler::<rasn_compiler::prelude::RasnBackend, _>::new_with_config(
        rasn_compiler::prelude::RasnConfig {
            generate_from_impls: true,
            no_std_compliant_bindings: true,
            ..Default::default()
        },
    )
    .add_asn_sources_by_path(
        (&[
            std::path::PathBuf::from("asn1/IVI-PDU-Descriptions.asn"),
            std::path::PathBuf::from("asn1/ISO19321IVIv3.1.asn"),
            std::path::PathBuf::from("asn1/ISO19321IVI-IS.asn"),
        ])
            .iter(),
    )
    .set_output_mode(rasn_compiler::OutputMode::SingleFile(
        out_path.join("ivim.rs"),
    ))
    .compile()?;

    rasn_compiler::Compiler::<rasn_compiler::prelude::RasnBackend, _>::new_with_config(
        rasn_compiler::prelude::RasnConfig {
            generate_from_impls: true,
            no_std_compliant_bindings: true,
            ..Default::default()
        },
    )
    .add_asn_sources_by_path(
        (&[std::path::PathBuf::from(
            "asn1/ISO17573-3(2021)EfcDataDictionary.asn",
        )])
            .iter(),
    )
    .set_output_mode(rasn_compiler::OutputMode::SingleFile(
        out_path.join("efc.rs"),
    ))
    .compile()?;

    rasn_compiler::Compiler::<rasn_compiler::prelude::RasnBackend, _>::new_with_config(
        rasn_compiler::prelude::RasnConfig {
            generate_from_impls: true,
            no_std_compliant_bindings: true,
            ..Default::default()
        },
    )
    .add_asn_sources_by_path(
        (&[std::path::PathBuf::from("asn1/ISO_14823-1 ed1_AnnexE.asn")]).iter(),
    )
    .set_output_mode(rasn_compiler::OutputMode::SingleFile(
        out_path.join("gdd.rs"),
    ))
    .compile()?;

    rasn_compiler::Compiler::<rasn_compiler::prelude::RasnBackend, _>::new_with_config(
        rasn_compiler::prelude::RasnConfig {
            generate_from_impls: true,
            no_std_compliant_bindings: true,
            custom_imports: vec!["alloc::boxed::Box".to_owned()],
            ..Default::default()
        },
    )
    .add_asn_sources_by_path((&[
        std::path::PathBuf::from("asn1/Ieee1609Dot2.asn"),
        std::path::PathBuf::from("asn1/Ieee1609Dot2BaseTypes.asn"),
    ]).iter())
    .set_output_mode(rasn_compiler::OutputMode::SingleFile(
        out_path.join("1609dot2.rs"),
    ))
    .compile()?;

    rasn_compiler::Compiler::<rasn_compiler::prelude::RasnBackend, _>::new_with_config(
        rasn_compiler::prelude::RasnConfig {
            generate_from_impls: true,
            no_std_compliant_bindings: true,
            custom_imports: vec!["alloc::boxed::Box".to_owned()],
            ..Default::default()
        },
    )
    .add_asn_sources_by_path((&[
        std::path::PathBuf::from("asn1/EtsiTs102941TypesLinkCertificate.asn")
    ]).iter())
    .set_output_mode(rasn_compiler::OutputMode::SingleFile(
        out_path.join("ca.rs"),
    ))
    .compile()?;

    let leap_second_db =
        reqwest::blocking::get("https://data.iana.org/time-zones/data/leap-seconds.list")?
            .error_for_status()?
            .text()?;
    let leap_second_file_path = out_path.join("leap_seconds.rs");
    let mut leap_second_file = std::fs::File::create(&leap_second_file_path)?;
    leap_second_file.write_all(b"pub const LEAP_SECONDS: &[(i64, i64)] = &[\n")?;
    for line in leap_second_db.lines() {
        if line.starts_with("#") {
            continue;
        }
        let parts = line.split_whitespace().collect::<Vec<_>>();
        leap_second_file.write_all(format!("    ({}, {}),\n", parts[0], parts[1]).as_bytes())?;
    }
    leap_second_file.write_all(b"];")?;

    Ok(())
}
