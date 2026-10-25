use core::ops::Deref;

#[derive(Debug)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct SecurityReport<B: super::crypto_backend::CryptoBackend> {
    provider_service: super::perms::ProviderService,
    generation_time: Option<chrono::DateTime<chrono::Utc>>,
    signature_verifies: bool,
    possible_chains: alloc::vec::Vec<Chain<B>>,
    validated_chain_index: Option<usize>,
}

impl<B: super::crypto_backend::CryptoBackend> SecurityReport<B> {
    pub fn provider_service(&self) -> super::perms::ProviderService {
        self.provider_service
    }

    pub fn generation_time(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.generation_time
    }

    pub fn signature_verifies(&self) -> bool {
        self.signature_verifies
    }

    pub fn possible_chains(&self) -> &[Chain<B>] {
        &self.possible_chains
    }
    
    pub fn validated_chain(&self) -> Option<&Chain<B>> {
        if let Some(validated_chain_index) = self.validated_chain_index {
            Some(&self.possible_chains[validated_chain_index])
        } else {
            None
        }
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct Chain<B: super::crypto_backend::CryptoBackend> {
    certs: alloc::vec::Vec<ChainEntry<B>>,
    ee_permissions_valid: bool,
}

impl<B: super::crypto_backend::CryptoBackend> Chain<B> {
    pub fn len(&self) -> usize {
        self.certs.len()
    }
    
    pub fn ee_cert(&self) -> &super::certs::CertificateReport<B> {
        &self.certs[self.certs.len()-1].cert
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct ChainEntry<B: super::crypto_backend::CryptoBackend> {
    cert: super::certs::CertificateReport<B>,
    is_root: bool,
    signature_verifies: bool,
    revoked: bool,
    expired: bool,
}

pub struct SecurityStore<B: super::crypto_backend::CryptoBackend> {
    certificates: alloc::collections::BTreeMap<
        [u8; 8],
        alloc::collections::BTreeSet<super::certs::CertificateReport<B>>,
    >,
    root_certificates: alloc::collections::BTreeMap<[u8; 8], super::certs::CertificateReport<B>>,
    crls: alloc::collections::BTreeMap<[u8; 8], super::certs::CRL<'static>>,
}

impl<B: super::crypto_backend::CryptoBackend> SecurityStore<B> where super::certs::CertificateReport<B>: Ord {
    pub fn new() -> Self {
        Self {
            certificates: Default::default(),
            root_certificates: Default::default(),
            crls: Default::default(),
        }
    }

    pub fn insert_cert(
        &mut self,
        certificate: super::certs::Certificate,
    ) -> Result<super::certs::CertificateReport<B>, &'static str> {
        let report = certificate.report()?;
        let set = self
            .certificates
            .entry(report.id8())
            .or_insert_with(Default::default);
        set.insert(report.clone());
        Ok(report)
    }

    pub fn add_root_ca(
        &mut self,
        certificate: super::certs::Certificate,
    ) -> Result<(), &'static str> {
        let report = certificate.report()?;
        if self.root_certificates.contains_key(&report.id8()) {
            return Err("duplicate root certificate HashID8");
        }
        self.root_certificates.insert(report.id8(), report);
        Ok(())
    }

    pub fn add_crl(&mut self, id8: [u8; 8], crl: super::certs::CRL<'static>) {
        self.crls.insert(id8, crl);
    }

    fn get_certificate<'a>(
        &'a self,
        id: [u8; 8],
        signature: &super::crypto::Signature<B>,
        hash: super::crypto::HashAlgorithm,
        tbs_bytes: &[u8],
    ) -> Option<(&'a super::certs::CertificateReport<B>, bool)> {
        let set = self.certificates.get(&id)?;
        if set.len() == 1 {
            Some((set.first().unwrap(), false))
        } else {
            for certificate in set.iter() {
                if signature.verify(
                    &certificate.public_key(),
                    hash,
                    tbs_bytes,
                    Some(certificate),
                ) {
                    return Some((certificate, true));
                }
            }
            None
        }
    }

    fn possible_chains(&self, cert: &super::certs::CertificateReport<B>) -> alloc::vec::Vec<Chain<B>> {
        if self.root_certificates.contains_key(&cert.id8()) {
            return alloc::vec![Chain {
                certs: alloc::vec![ChainEntry {
                    cert: cert.clone(),
                    is_root: true,
                    signature_verifies: true,
                    revoked: false,
                    expired: false,
                }],
                ee_permissions_valid: true,
            }];
        }
        match cert.signature() {
            super::certs::CertificateSignature::Unsigned => {
                alloc::vec![Chain {
                    certs: alloc::vec![ChainEntry {
                        cert: cert.clone(),
                        is_root: false,
                        signature_verifies: false,
                        revoked: false,
                        expired: false,
                    }],
                    ee_permissions_valid: false,
                }]
            }
            super::certs::CertificateSignature::Unknown => {
                alloc::vec![Chain {
                    certs: alloc::vec![ChainEntry {
                        cert: cert.clone(),
                        is_root: false,
                        signature_verifies: false,
                        revoked: false,
                        expired: false,
                    }],
                    ee_permissions_valid: false
                }]
            }
            super::certs::CertificateSignature::SelfSigned { verifies } => {
                alloc::vec![Chain {
                    certs: alloc::vec![ChainEntry {
                        cert: cert.clone(),
                        is_root: false,
                        signature_verifies: *verifies,
                        revoked: false,
                        expired: false
                    }],
                    ee_permissions_valid: false
                }]
            }
            super::certs::CertificateSignature::Parent {
                id8,
                hash_alg,
                signature,
                tbs_bytes,
            } => {
                if let Some(root) = self.root_certificates.get(id8) {
                    alloc::vec![Chain {
                        certs: alloc::vec![
                            ChainEntry {
                                cert: root.clone(),
                                is_root: true,
                                signature_verifies: true,
                                revoked: false,
                                expired: false
                            },
                            ChainEntry {
                                cert: cert.clone(),
                                is_root: false,
                                signature_verifies: signature.verify(
                                    root.public_key(),
                                    *hash_alg,
                                    tbs_bytes,
                                    Some(root)
                                ),
                                revoked: false,
                                expired: false
                            }
                        ],
                        ee_permissions_valid: false
                    }]
                } else if let Some(certs) = self.certificates.get(id8) {
                    let mut new_chains = alloc::vec![];
                    for parent in certs.iter() {
                        for mut chain in self.possible_chains(parent) {
                            chain.certs.push(ChainEntry {
                                cert: cert.clone(),
                                is_root: false,
                                signature_verifies: signature.verify(
                                    parent.public_key(),
                                    *hash_alg,
                                    tbs_bytes,
                                    Some(parent),
                                ),
                                revoked: false,
                                expired: false,
                            });
                            new_chains.push(chain);
                        }
                    }
                    new_chains
                } else {
                    alloc::vec![Chain {
                        certs: alloc::vec![ChainEntry {
                            cert: cert.clone(),
                            is_root: false,
                            signature_verifies: false,
                            revoked: false,
                            expired: false,
                        }],
                        ee_permissions_valid: false
                    }]
                }
            }
        }
    }

    fn validate_chain(&self, chain: &mut Chain<B>, now: chrono::DateTime<chrono::Utc>) {
        if chain.certs.is_empty() {
            return;
        }

        let root_crl = if chain.certs[0].is_root {
            self.crls.get(&chain.certs[0].cert.id8())
        } else {
            None
        };

        for entry in chain.certs.iter_mut() {
            if let Some(crl) = root_crl {
                entry.revoked = crl.is_revoked(entry.cert.id8())
            }
            if entry.cert.valid_from() > &now {
                entry.expired = true;
            } else if entry.cert.valid_until() < &now {
                entry.expired = true;
            }
        }

        let ee_index = chain.certs.len() - 1;
        let permissions_valid = if chain.certs[ee_index].is_root {
            true
        } else if ee_index == 0 {
            false
        } else {
            let ee_cert = &chain.certs[ee_index].cert;
            chain.certs[..ee_index]
                .iter()
                .enumerate()
                .all(|(parent_index, parent_entry)| {
                    let chain_length = (ee_index - parent_index) as u64;
                    ee_cert.app_permissions_authorized_by(&parent_entry.cert, chain_length)
                })
        };
        chain.ee_permissions_valid = permissions_valid;
    }

    pub fn security_report(
        &mut self,
        data: &rasn_its::ieee1609dot2::SignedData,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<SecurityReport<B>, &'static str> {
        let sig = super::crypto::Signature::parse(&data.signature)?;
        let hash: super::crypto::HashAlgorithm = data.hash_id.try_into()?;
        let tbs_bytes = rasn::oer::encode(&data.tbs_data).unwrap();
        let (certificate, signature_verifies) = match &data.signer {
            rasn_its::ieee1609dot2::SignerIdentifier::SelfSigned(()) => {
                return Err("message cannot be self-signed");
            }
            rasn_its::ieee1609dot2::SignerIdentifier::Digest(d) => match self
                .get_certificate(***d, &sig, hash, &tbs_bytes)
            {
                Some((c, true)) => (Some(c.clone()), true),
                Some((c, false)) => {
                    let signature_verifies = sig.verify(c.public_key(), hash, &tbs_bytes, Some(&c));
                    (Some(c.clone()), signature_verifies)
                }
                None => (None, false),
            },
            rasn_its::ieee1609dot2::SignerIdentifier::Certificate(sc) => {
                let certificate =
                    rasn_its::ts103097::EtsiTs103097Certificate::try_from(sc.0[0].clone())
                        .map_err(|_| "invalid signing certificate")?;
                let certificate = self.insert_cert(super::certs::Certificate(
                    alloc::borrow::Cow::Owned(certificate),
                ))?;
                let signature_verifies = sig.verify(
                    certificate.public_key(),
                    hash,
                    &tbs_bytes,
                    Some(&certificate),
                );
                (Some(certificate), signature_verifies)
            }
            _ => return Err("unsupported signer identifier"),
        };

        let mut possible_chains = match &certificate {
            Some(certificate) => self.possible_chains(certificate),
            None => alloc::vec![],
        };

        for chain in possible_chains.iter_mut() {
            self.validate_chain(chain, now);
        }

        let validated_chain_index = possible_chains.iter().enumerate().find(|(_, c)| {
            c.ee_permissions_valid
                && c.certs.len() != 0
                && c.certs.iter().all(|cert| !cert.revoked && !cert.expired && cert.signature_verifies)
                && c.certs[0].is_root
        }).map(|(i, _)| i);

        let report = SecurityReport {
            provider_service: (&data.tbs_data.header_info.psid).into(),
            generation_time: data
                .tbs_data
                .header_info
                .generation_time
                .as_ref()
                .map(super::certs::time64_to_utc),
            signature_verifies,
            possible_chains,
            validated_chain_index,
        };

        Ok(report)
    }
}

pub fn sign_message<B: super::crypto_backend::CryptoBackend>(
    data: crate::geo_networking::CommonHeader,
    header_info: rasn_its::ieee1609dot2::HeaderInfo,
    private_key: &super::crypto::PrivateKey<B>,
    certificate: &super::certs::Certificate,
    full_cert: bool
) -> Option<crate::geo_networking::SignedPacket> {
    let mut common_header = alloc::vec![];
    data.write(&mut common_header);

    let tbs_data = rasn_its::ieee1609dot2::ToBeSignedData {
        header_info,
        payload: rasn_its::ieee1609dot2::SignedDataPayload::builder()
            .data(rasn_its::ieee1609dot2::Ieee1609Dot2Data {
                protocol_version: 3,
                content: rasn_its::ieee1609dot2::Ieee1609Dot2Content::UnsecuredData(
                    rasn_its::ieee1609dot2::base_types::Opaque(common_header.into())
                )
            }).build().unwrap()
    };
    let tbs_bytes = rasn::oer::encode(&tbs_data).unwrap();

    let signature = private_key.sign(&tbs_bytes, Some(&certificate))?;

    Some(crate::geo_networking::SignedPacket(rasn_its::ieee1609dot2::SignedData {
        hash_id: private_key.hash_algorithm().into(),
        tbs_data,
        signer: if full_cert {
            rasn_its::ieee1609dot2::SignerIdentifier::Certificate(
                rasn_its::ieee1609dot2::SequenceOfCertificate(alloc::vec![
                    certificate.as_cert().deref().clone(),
                ].into())
            )
        } else {
            rasn_its::ieee1609dot2::SignerIdentifier::Digest(
                rasn_its::ieee1609dot2::base_types::HashedId8(certificate.id8()?.into()),
            )
        },
        signature: signature.as_signature()
    }))
}