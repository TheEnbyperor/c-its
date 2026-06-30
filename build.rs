

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR")?);

    rasn_compiler::Compiler::<rasn_compiler::prelude::RasnBackend, _>::new_with_config(
        rasn_compiler::prelude::RasnConfig {
            generate_from_impls: true,
            no_std_compliant_bindings: true,
            ..Default::default()
        },
    )
        .add_asn_sources_by_path((&[
            std::path::PathBuf::from("asn1/ETSI-ITS-CDD.asn"),
            std::path::PathBuf::from("asn1/CAM-PDU-Descriptions.asn"),
            std::path::PathBuf::from("asn1/DENM-PDU-Description.asn"),
        ]).iter())
        .set_output_mode(rasn_compiler::OutputMode::SingleFile(
            out_path.join("cam_denm.rs")
        ))
        .compile()?;

    rasn_compiler::Compiler::<rasn_compiler::prelude::RasnBackend, _>::new_with_config(
        rasn_compiler::prelude::RasnConfig {
            generate_from_impls: true,
            no_std_compliant_bindings: true,
            ..Default::default()
        },
    )
        .add_asn_sources_by_path((&[
            std::path::PathBuf::from("asn1/MAPEM-PDU-Descriptions.asn"),
            std::path::PathBuf::from("asn1/DSRC.asn"),
        ]).iter())
        .set_output_mode(rasn_compiler::OutputMode::SingleFile(
            out_path.join("mapem.rs")
        ))
        .compile()?;

    rasn_compiler::Compiler::<rasn_compiler::prelude::RasnBackend, _>::new_with_config(
        rasn_compiler::prelude::RasnConfig {
            generate_from_impls: true,
            no_std_compliant_bindings: true,
            ..Default::default()
        },
    )
        .add_asn_sources_by_path((&[
            std::path::PathBuf::from("asn1/SPATEM-PDU-Descriptions.asn"),
        ]).iter())
        .set_output_mode(rasn_compiler::OutputMode::SingleFile(
            out_path.join("spatem.rs")
        ))
        .compile()?;

    rasn_compiler::Compiler::<rasn_compiler::prelude::RasnBackend, _>::new_with_config(
        rasn_compiler::prelude::RasnConfig {
            generate_from_impls: true,
            no_std_compliant_bindings: true,
            ..Default::default()
        },
    )
        .add_asn_sources_by_path((&[
            std::path::PathBuf::from("asn1/IVI-PDU-Descriptions.asn"),
            std::path::PathBuf::from("asn1/ISO19321IVIv3.1.asn"),
            std::path::PathBuf::from("asn1/ISO19321IVI-IS.asn"),
        ]).iter())
        .set_output_mode(rasn_compiler::OutputMode::SingleFile(
            out_path.join("ivim.rs")
        ))
        .compile()?;

    rasn_compiler::Compiler::<rasn_compiler::prelude::RasnBackend, _>::new_with_config(
        rasn_compiler::prelude::RasnConfig {
            generate_from_impls: true,
            no_std_compliant_bindings: true,
            ..Default::default()
        },
    )
        .add_asn_sources_by_path((&[
            std::path::PathBuf::from("asn1/ISO17573-3(2021)EfcDataDictionary.asn"),
        ]).iter())
        .set_output_mode(rasn_compiler::OutputMode::SingleFile(
            out_path.join("efc.rs")
        ))
        .compile()?;

    rasn_compiler::Compiler::<rasn_compiler::prelude::RasnBackend, _>::new_with_config(
        rasn_compiler::prelude::RasnConfig {
            generate_from_impls: true,
            no_std_compliant_bindings: true,
            ..Default::default()
        },
    )
        .add_asn_sources_by_path((&[
            std::path::PathBuf::from("asn1/ISO_14823-1 ed1_AnnexE.asn"),
        ]).iter())
        .set_output_mode(rasn_compiler::OutputMode::SingleFile(
            out_path.join("gdd.rs")
        ))
        .compile()?;

    Ok(())
}