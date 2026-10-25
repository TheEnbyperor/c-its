use digest::Digest;
#[cfg(feature = "json")]
use serde::ser::SerializeStruct;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub enum HashAlgorithm {
    #[cfg_attr(feature = "json", serde(rename = "sha256"))]
    Sha256,
    #[cfg_attr(feature = "json", serde(rename = "sha384"))]
    Sha384,
    #[cfg_attr(feature = "json", serde(rename = "sm3"))]
    Sm3,
}

impl TryFrom<&rasn_its::ieee1609dot2::base_types::HashAlgorithm> for HashAlgorithm {
    type Error = &'static str;

    fn try_from(
        value: &rasn_its::ieee1609dot2::base_types::HashAlgorithm,
    ) -> Result<Self, Self::Error> {
        match value {
            rasn_its::ieee1609dot2::base_types::HashAlgorithm::Sha256 => Ok(Self::Sha256),
            rasn_its::ieee1609dot2::base_types::HashAlgorithm::Sha384 => Ok(Self::Sha384),
            rasn_its::ieee1609dot2::base_types::HashAlgorithm::Sm3 => Ok(Self::Sm3),
            _ => Err("unknown hash algorithm"),
        }
    }
}

impl TryFrom<rasn_its::ieee1609dot2::base_types::HashAlgorithm> for HashAlgorithm {
    type Error = &'static str;

    fn try_from(
        value: rasn_its::ieee1609dot2::base_types::HashAlgorithm,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl Into<rasn_its::ieee1609dot2::base_types::HashAlgorithm> for HashAlgorithm {
    fn into(self) -> rasn_its::ieee1609dot2::base_types::HashAlgorithm {
        match self {
            Self::Sha256 => rasn_its::ieee1609dot2::base_types::HashAlgorithm::Sha256,
            Self::Sha384 => rasn_its::ieee1609dot2::base_types::HashAlgorithm::Sha384,
            Self::Sm3 => rasn_its::ieee1609dot2::base_types::HashAlgorithm::Sm3,
        }
    }
}

#[derive(Debug, Clone)]
pub enum PrivateKey<B: super::crypto_backend::CryptoBackend> {
    P256(B::P256PrivateKey),
    P384(B::P384PrivateKey),
    BP256(B::BP256PrivateKey),
    BP384(B::BP384PrivateKey),
    SM2(B::SM2PrivateKey),
}

impl<B: super::crypto_backend::CryptoBackend> PrivateKey<B> {
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            Self::P256(_) | Self::BP256(_) => HashAlgorithm::Sha256,
            Self::P384(_) | Self::BP384(_) => HashAlgorithm::Sha384,
            Self::SM2(_) => HashAlgorithm::Sm3,
        }
    }

    pub fn public_key(&self) -> PublicKey<B> {
        use super::crypto_backend::PrivateKey;
        match self {
            Self::P256(p) => PublicKey::P256(p.public_key()),
            Self::P384(p) => PublicKey::P384(p.public_key()),
            Self::BP256(p) => PublicKey::BP256(p.public_key()),
            Self::BP384(p) => PublicKey::BP384(p.public_key()),
            Self::SM2(p) => PublicKey::SM2(p.public_key()),
        }
    }

    #[cfg(feature = "build-binary")]
    pub fn from_bytes_pem(b: &[u8]) -> Result<Self, &'static str> {
        use elliptic_curve::pkcs8::AssociatedOid;
        use elliptic_curve::pkcs8::DecodePrivateKey;
        use pem_rfc7468::PemLabel;
        use sec1::der::Decode;
        use super::crypto_backend::PrivateKey;

        let (label, der) = pem_rfc7468::decode_vec(&b).map_err(|_| "invalid PEM data")?;
        if label != elliptic_curve::pkcs8::PrivateKeyInfoRef::PEM_LABEL {
            return Err("not a private key PEM block");
        }
        let info = elliptic_curve::pkcs8::PrivateKeyInfoRef::from_der(&der)
            .map_err(|_| "invalid private key")?;
        if info.algorithm.oid == elliptic_curve::ALGORITHM_OID {
            let curve_oid = info
                .algorithm
                .parameters
                .ok_or("missing EC parameters")?
                .decode_as::<elliptic_curve::pkcs8::ObjectIdentifier>()
                .map_err(|_| "invalid EC parameters")?;

            match curve_oid {
                p256::NistP256::OID => {
                    let key =
                        B::P256PrivateKey::from_pkcs8_der(&der).ok_or("invalid P-256 key")?;
                    Ok(Self::P256(key))
                }
                p384::NistP384::OID => {
                    let key =
                        B::P384PrivateKey::from_pkcs8_der(&der).ok_or("invalid P-384 key")?;
                    Ok(Self::P384(key))
                }
                bp256::r1::BrainpoolP256r1::OID => {
                    let key =
                        B::BP256PrivateKey::from_pkcs8_der(&der).ok_or("invalid Brainpool256r1 key")?;
                    Ok(Self::BP256(key))
                }
                bp384::r1::BrainpoolP384r1::OID => {
                    let key =
                        B::BP384PrivateKey::from_pkcs8_der(&der).ok_or("invalid Brainpool384r1 key")?;
                    Ok(Self::BP384(key))
                }
                sm2::Sm2::OID => {
                    let key =
                        B::SM2PrivateKey::from_pkcs8_der(&der).ok_or("invalid SM2 key")?;
                    Ok(Self::SM2(key))
                }
                _ => Err("unsupported curve"),
            }
        } else {
            Err("unsupported curve")
        }
    }

    #[cfg(feature = "build-binary")]
    pub fn as_bytes_pem(&self) -> alloc::vec::Vec<u8> {
        use elliptic_curve::pkcs8::PrivateKeyInfoRef;
        use pem_rfc7468::PemLabel;
        use super::crypto_backend::PrivateKey;

        let der = match self {
            Self::P256(p) => p.to_pkcs8_der(),
            Self::P384(p) => p.to_pkcs8_der(),
            Self::BP256(p) => p.to_pkcs8_der(),
            Self::BP384(p) => p.to_pkcs8_der(),
            Self::SM2(p) => p.to_pkcs8_der(),
        }
        .unwrap();
        pem_rfc7468::encode_string(PrivateKeyInfoRef::PEM_LABEL, Default::default(), &der)
            .unwrap()
            .into_bytes()
    }

    pub fn sign(
        &self,
        tbs_bytes: &[u8],
        certificate: Option<&super::certs::Certificate>,
    ) -> Option<Signature<B>> {
        use super::crypto_backend::PrivateKey;

        let signer_info = match certificate {
            Some(c) => c.to_bytes(),
            None => alloc::vec::Vec::default(),
        };
        let pre_hashed = match self.hash_algorithm() {
            HashAlgorithm::Sha256 => {
                let mut h = sha2::Sha256::new();
                h.update(sha2::Sha256::digest(tbs_bytes).as_slice());
                h.update(sha2::Sha256::digest(signer_info).as_slice());
                h.finalize().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut h = sha2::Sha384::new();
                h.update(sha2::Sha384::digest(tbs_bytes).as_slice());
                h.update(sha2::Sha384::digest(signer_info).as_slice());
                h.finalize().to_vec()
            }
            HashAlgorithm::Sm3 => {
                let Self::SM2(pk) = self else {
                    return None;
                };
                let h = sm3::Sm3::digest(signer_info);
                let Some(z) = sm2_hash_z::<B>(
                    if certificate.is_some() {
                        h.as_slice()
                    } else {
                        b"1234567812345678"
                    },
                    &pk.public_key(),
                ) else {
                    return None;
                };
                sm3::Sm3::new_with_prefix(z)
                    .chain_update(tbs_bytes)
                    .finalize()
                    .to_vec()
            }
        };

        match self {
            Self::P256(pk) => {
                let s = pk.sign_prehashed(&pre_hashed)?;
                Some(Signature::P256(s))
            }
            Self::P384(pk) => {
                let s = pk.sign_prehashed(&pre_hashed)?;
                Some(Signature::P384(s))
            }
            Self::BP256(pk) => {
                let s = pk.sign_prehashed(&pre_hashed)?;
                Some(Signature::BP256(s))
            }
            Self::BP384(pk) => {
                let s = pk.sign_prehashed(&pre_hashed)?;
                Some(Signature::BP384(s))
            }
            Self::SM2(pk) => {
                let s = pk.sign_prehashed(&pre_hashed)?;
                Some(Signature::SM2(s))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum PublicKey<B: super::crypto_backend::CryptoBackend> {
    P256(B::P256PublicKey),
    P384(B::P384PublicKey),
    BP256(B::BP256PublicKey),
    BP384(B::BP384PublicKey),
    SM2(B::SM2PublicKey),
}

impl<B: super::crypto_backend::CryptoBackend> PublicKey<B> {
    pub fn parse(
        key: &rasn_its::ieee1609dot2::base_types::PublicVerificationKey,
    ) -> Result<Self, &'static str> {
        use super::crypto_backend::PublicKey;
        match key {
            rasn_its::ieee1609dot2::base_types::PublicVerificationKey::EcdsaNistP256(key) => {
                let mut v = [0u8; 65];
                let encoded_point = match key {
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY0(point) => {
                        v[0] = 0x02;
                        v[1..33].copy_from_slice(point.as_ref());
                        &v[0..33]
                    }
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY1(point) => {
                        v[0] = 0x03;
                        v[1..33].copy_from_slice(point.as_ref());
                        &v[0..33]
                    }
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::Uncompressed(point) => {
                        v[0] = 0x04;
                        v[1..33].copy_from_slice(point.x.as_ref());
                        v[33..65].copy_from_slice(point.y.as_ref());
                        &v
                    }
                    _ => return Err("invalid curve point"),
                };
                Ok(Self::P256(
                    B::P256PublicKey::from_sec1_point(&encoded_point).ok_or("invalid curve point")?,
                ))
            }
            rasn_its::ieee1609dot2::base_types::PublicVerificationKey::EcdsaBrainpoolP256r1(
                key,
            ) => {
                let mut v = [0u8; 65];
                let encoded_point = match key {
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY0(point) => {
                        v[0] = 0x02;
                        v[1..33].copy_from_slice(point.as_ref());
                        &v[0..33]
                    }
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY1(point) => {
                        v[0] = 0x03;
                        v[1..33].copy_from_slice(point.as_ref());
                        &v[0..33]
                    }
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::Uncompressed(point) => {
                        v[0] = 0x04;
                        v[1..33].copy_from_slice(point.x.as_ref());
                        v[33..65].copy_from_slice(point.y.as_ref());
                        &v
                    }
                    _ => return Err("invalid curve point"),
                };
                Ok(Self::BP256(
                    B::BP256PublicKey::from_sec1_point(&encoded_point).ok_or("invalid curve point")?,
                ))
            }
            rasn_its::ieee1609dot2::base_types::PublicVerificationKey::EcdsaNistP384(key) => {
                let mut v = [0u8; 97];
                let encoded_point = match key {
                    rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::CompressedY0(point) => {
                        v[0] = 0x02;
                        v[1..33].copy_from_slice(point.as_ref());
                        &v[0..49]
                    }
                    rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::CompressedY1(point) => {
                        v[0] = 0x03;
                        v[1..33].copy_from_slice(point.as_ref());
                        &v[0..49]
                    }
                    rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::Uncompressed(point) => {
                        v[0] = 0x04;
                        v[1..49].copy_from_slice(point.x.as_ref());
                        v[49..97].copy_from_slice(point.y.as_ref());
                        &v
                    }
                    _ => return Err("invalid curve point"),
                };
                Ok(Self::P384(
                    B::P384PublicKey::from_sec1_point(&encoded_point).ok_or("invalid curve point")?,
                ))
            }
            rasn_its::ieee1609dot2::base_types::PublicVerificationKey::EcdsaBrainpoolP384r1(
                key,
            ) => {
                let mut v = [0u8; 97];
                let encoded_point = match key {
                    rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::CompressedY0(point) => {
                        v[0] = 0x02;
                        v[1..33].copy_from_slice(point.as_ref());
                        &v[0..49]
                    }
                    rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::CompressedY1(point) => {
                        v[0] = 0x03;
                        v[1..33].copy_from_slice(point.as_ref());
                        &v[0..49]
                    }
                    rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::Uncompressed(point) => {
                        v[0] = 0x04;
                        v[1..49].copy_from_slice(point.x.as_ref());
                        v[49..97].copy_from_slice(point.y.as_ref());
                        &v
                    }
                    _ => return Err("invalid curve point"),
                };
                Ok(Self::BP384(
                    B::BP384PublicKey::from_sec1_point(&encoded_point).ok_or("invalid curve point")?,
                ))
            }
            rasn_its::ieee1609dot2::base_types::PublicVerificationKey::EcsigSm2(key) => {
                let mut v = [0u8; 65];
                let encoded_point = match key {
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY0(point) => {
                        v[0] = 0x02;
                        v[1..33].copy_from_slice(point.as_ref());
                        &v[0..33]
                    }
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY1(point) => {
                        v[0] = 0x03;
                        v[1..33].copy_from_slice(point.as_ref());
                        &v[0..33]
                    }
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::Uncompressed(point) => {
                        v[0] = 0x04;
                        v[1..33].copy_from_slice(point.x.as_ref());
                        v[33..65].copy_from_slice(point.y.as_ref());
                        &v
                    }
                    _ => return Err("invalid curve point"),
                };
                Ok(Self::SM2(
                    B::SM2PublicKey::from_sec1_point(&encoded_point).ok_or("invalid curve point")?,
                ))
            }
            _ => Err("unsupported public key type"),
        }
    }

    pub fn encode(&self) -> rasn_its::ieee1609dot2::base_types::PublicVerificationKey {
        use crate::security::crypto_backend::PublicKey;
        match self {
            Self::P256(pk) => {
                rasn_its::ieee1609dot2::base_types::PublicVerificationKey::EcdsaNistP256(
                    if pk.even_y() {
                        rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY0(
                            pk.x().into()
                        )
                    } else {
                        rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY1(
                            pk.x().into()
                        )
                    }
                )
            }
            Self::P384(pk) => {
                rasn_its::ieee1609dot2::base_types::PublicVerificationKey::EcdsaNistP384(
                    if pk.even_y() {
                        rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::CompressedY0(
                            pk.x().into()
                        )
                    } else {
                        rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::CompressedY1(
                            pk.x().into()
                        )
                    }
                )
            }
            Self::BP256(pk) => {
                rasn_its::ieee1609dot2::base_types::PublicVerificationKey::EcdsaBrainpoolP256r1(
                    if pk.even_y() {
                        rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY0(
                            pk.x().into()
                        )
                    } else {
                        rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY1(
                            pk.x().into()
                        )
                    }
                )
            }
            Self::BP384(pk) => {
                rasn_its::ieee1609dot2::base_types::PublicVerificationKey::EcdsaBrainpoolP384r1(
                   if pk.even_y() {
                        rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::CompressedY0(
                            pk.x().into(),
                        )
                    } else {
                        rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::CompressedY1(
                            pk.x().into(),
                        )
                    }
                )
            }
            Self::SM2(pk) => {
                rasn_its::ieee1609dot2::base_types::PublicVerificationKey::EcsigSm2(
                    if pk.even_y() {
                        rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY0(
                            pk.x().into(),
                        )
                    } else {
                        rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY1(
                            pk.x().into(),
                        )
                    }
                )
            }
        }
    }

    pub fn encode_encryption(
        &self,
    ) -> Result<rasn_its::ieee1609dot2::base_types::PublicEncryptionKey, &'static str> {
        use crate::security::crypto_backend::PublicKey;
        Ok(match self {
            Self::P256(pk) => {
                rasn_its::ieee1609dot2::base_types::PublicEncryptionKey::builder()
                    .public_key(rasn_its::ieee1609dot2::base_types::BasePublicEncryptionKey::EciesNistP256(
                        if pk.even_y() {
                            rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY0(pk.x().into())
                        } else {
                            rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY1(pk.x().into())
                        }
                    ))
                    .supported_symm_alg(rasn_its::ieee1609dot2::base_types::SymmAlgorithm::Aes128Ccm)
                    .build()
            }
            Self::BP256(pk) => {
                rasn_its::ieee1609dot2::base_types::PublicEncryptionKey::builder()
                    .public_key(rasn_its::ieee1609dot2::base_types::BasePublicEncryptionKey::EciesBrainpoolP256r1(
                        if pk.even_y() {
                            rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY0(pk.x().into())
                        } else {
                            rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY1(pk.x().into())
                        }
                    ))
                    .supported_symm_alg(rasn_its::ieee1609dot2::base_types::SymmAlgorithm::Aes128Ccm)
                    .build()
            }
            Self::SM2(pk) => {
                rasn_its::ieee1609dot2::base_types::PublicEncryptionKey::builder()
                    .public_key(rasn_its::ieee1609dot2::base_types::BasePublicEncryptionKey::EcencSm2(
                        if pk.even_y() {
                            rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY0(pk.x().into())
                        } else {
                            rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY1(pk.x().into())
                        }
                    ))
                    .supported_symm_alg(rasn_its::ieee1609dot2::base_types::SymmAlgorithm::Sm4Ccm)
                    .build()
            }
            _ => return Err("unsupported curve for encryption keys"),
        })
    }
}

impl<B: super::crypto_backend::CryptoBackend> core::cmp::PartialEq for PublicKey<B> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::P256(k1), Self::P256(k2)) => k1 == k2,
            (Self::P384(k1), Self::P384(k2)) => k1 == k2,
            (Self::BP256(k1), Self::BP256(k2)) => k1 == k2,
            (Self::BP384(k1), Self::BP384(k2)) => k1 == k2,
            (Self::SM2(k1), Self::SM2(k2)) => k1 == k2,
            _ => false,
        }
    }
}

impl<B: super::crypto_backend::CryptoBackend> core::cmp::Eq for PublicKey<B> {}

impl<B: super::crypto_backend::CryptoBackend> core::cmp::PartialOrd for PublicKey<B> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        match (self, other) {
            (Self::P256(k1), Self::P256(k2)) => k1.partial_cmp(k2),
            (Self::P384(k1), Self::P384(k2)) => k1.partial_cmp(k2),
            (Self::BP256(k1), Self::BP256(k2)) => k1.partial_cmp(k2),
            (Self::BP384(k1), Self::BP384(k2)) => k1.partial_cmp(k2),
            (Self::SM2(k1), Self::SM2(k2)) => k1.partial_cmp(k2),
                // .to_sec1_point(false)
                // .partial_cmp(&k2.to_sec1_point(false)),
            _ => None,
        }
    }
}

impl<B: super::crypto_backend::CryptoBackend> core::cmp::Ord for PublicKey<B> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        if let Some(cmp) = self.partial_cmp(other) {
            cmp
        } else {
            match (self, other) {
                (Self::P256(_), _) => core::cmp::Ordering::Less,
                (Self::P384(_), Self::P256(_)) => core::cmp::Ordering::Greater,
                (Self::P384(_), _) => core::cmp::Ordering::Less,
                (Self::BP256(_), Self::P256(_)) => core::cmp::Ordering::Greater,
                (Self::BP256(_), Self::P384(_)) => core::cmp::Ordering::Greater,
                (Self::BP256(_), _) => core::cmp::Ordering::Less,
                (Self::BP384(_), Self::P256(_)) => core::cmp::Ordering::Greater,
                (Self::BP384(_), Self::P384(_)) => core::cmp::Ordering::Greater,
                (Self::BP384(_), Self::BP256(_)) => core::cmp::Ordering::Greater,
                (Self::BP384(_), _) => core::cmp::Ordering::Less,
                (Self::SM2(_), _) => core::cmp::Ordering::Greater,
            }
        }
    }
}

#[cfg(feature = "json")]
fn compressed_point<const FIELD_SIZE: usize, S>(
    key: &impl super::crypto_backend::PublicKey<FIELD_SIZE, S>,
) -> alloc::vec::Vec<u8> {
    let mut point = alloc::vec::Vec::with_capacity(FIELD_SIZE + 1);
    point.push(if key.even_y() { 0x02 } else { 0x03 });
    point.extend_from_slice(&key.x());
    point
}

#[cfg(feature = "json")]
impl<B: super::crypto_backend::CryptoBackend> serde::Serialize for PublicKey<B> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut struct_serializer = serializer.serialize_struct("PublicKey", 2)?;
        match self {
            Self::P256(k) => {
                struct_serializer.serialize_field("curve", "nistP256")?;
                struct_serializer
                    .serialize_field("k", &hex::encode_upper(compressed_point(k)))?;
            }
            Self::P384(k) => {
                struct_serializer.serialize_field("curve", "nistP384")?;
                struct_serializer
                    .serialize_field("k", &hex::encode_upper(compressed_point(k)))?;
            }
            Self::BP256(k) => {
                struct_serializer.serialize_field("curve", "brainpoolP256r1")?;
                struct_serializer
                    .serialize_field("k", &hex::encode_upper(compressed_point(k)))?;
            }
            Self::BP384(k) => {
                struct_serializer.serialize_field("curve", "brainpoolP384r1")?;
                struct_serializer
                    .serialize_field("k", &hex::encode_upper(compressed_point(k)))?;
            }
            Self::SM2(k) => {
                struct_serializer.serialize_field("curve", "sm2")?;
                struct_serializer
                    .serialize_field("k", &hex::encode_upper(compressed_point(k)))?;
            }
        }
        struct_serializer.end()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Signature<B: super::crypto_backend::CryptoBackend> {
    P256(B::P256Signature),
    P384(B::P384Signature),
    BP256(B::BP256Signature),
    BP384(B::BP384Signature),
    SM2(B::SM2Signature),
}

impl<B: super::crypto_backend::CryptoBackend> core::cmp::PartialOrd for Signature<B> where Signature<B>: PartialEq {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        use super::crypto_backend::Signature;
        match (self, other) {
            (Self::P256(s1), Self::P256(s2)) => match s1.r().cmp(&s2.r()) {
                core::cmp::Ordering::Less => Some(core::cmp::Ordering::Less),
                core::cmp::Ordering::Greater => Some(core::cmp::Ordering::Greater),
                core::cmp::Ordering::Equal => Some(s1.s().cmp(&s2.s())),
            },
            (Self::P384(s1), Self::P384(s2)) => match s1.r().cmp(&s2.r()) {
                core::cmp::Ordering::Less => Some(core::cmp::Ordering::Less),
                core::cmp::Ordering::Greater => Some(core::cmp::Ordering::Greater),
                core::cmp::Ordering::Equal => Some(s1.s().cmp(&s2.s())),
            },
            (Self::BP256(s1), Self::BP256(s2)) => match s1.r().cmp(&s2.r()) {
                core::cmp::Ordering::Less => Some(core::cmp::Ordering::Less),
                core::cmp::Ordering::Greater => Some(core::cmp::Ordering::Greater),
                core::cmp::Ordering::Equal => Some(s1.s().cmp(&s2.s())),
            },
            (Self::BP384(s1), Self::BP384(s2)) => match s1.r().cmp(&s2.r()) {
                core::cmp::Ordering::Less => Some(core::cmp::Ordering::Less),
                core::cmp::Ordering::Greater => Some(core::cmp::Ordering::Greater),
                core::cmp::Ordering::Equal => Some(s1.s().cmp(&s2.s())),
            },
            (Self::SM2(s1), Self::SM2(s2)) => match s1.r().cmp(&s2.r()) {
                core::cmp::Ordering::Less => Some(core::cmp::Ordering::Less),
                core::cmp::Ordering::Greater => Some(core::cmp::Ordering::Greater),
                core::cmp::Ordering::Equal => Some(s1.s().cmp(&s2.s())),
            },
            _ => None,
        }
    }
}

impl<B: super::crypto_backend::CryptoBackend> core::cmp::Ord for Signature<B> where Signature<B>: Eq {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        if let Some(cmp) = self.partial_cmp(other) {
            cmp
        } else {
            match (self, other) {
                (Self::P256(_), _) => core::cmp::Ordering::Less,
                (Self::P384(_), Self::P256(_)) => core::cmp::Ordering::Greater,
                (Self::P384(_), _) => core::cmp::Ordering::Less,
                (Self::BP256(_), Self::P256(_)) => core::cmp::Ordering::Greater,
                (Self::BP256(_), Self::P384(_)) => core::cmp::Ordering::Greater,
                (Self::BP256(_), _) => core::cmp::Ordering::Less,
                (Self::BP384(_), Self::P256(_)) => core::cmp::Ordering::Greater,
                (Self::BP384(_), Self::P384(_)) => core::cmp::Ordering::Greater,
                (Self::BP384(_), Self::BP256(_)) => core::cmp::Ordering::Greater,
                (Self::BP384(_), _) => core::cmp::Ordering::Less,
                (Self::SM2(_), _) => core::cmp::Ordering::Greater,
            }
        }
    }
}

fn sm2_hash_z<B: super::crypto_backend::CryptoBackend>(
    distid: &[u8],
    public_key: &B::SM2PublicKey,
) -> Option<digest::Output<sm3::Sm3>> {
    use super::crypto_backend::PublicKey;
    const SM2_EQUATION_A: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFC,
    ];
    const SM2_EQUATION_B: [u8; 32] = [
        0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09,
        0xA7, 0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94,
        0x0E, 0x93,
    ];
    const SM2_GENERATOR_X: [u8; 32] = [
        0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9,
        0x94, 0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C,
        0x74, 0xC7,
    ];
    const SM2_GENERATOR_Y: [u8; 32] = [
        0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21,
        0x53, 0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39,
        0xF0, 0xA0,
    ];
    let entla: u16 = distid
        .len()
        .checked_mul(8)
        .and_then(|l| l.try_into().ok())?;
    let mut sm3 = sm3::Sm3::new();
    sm3.update(entla.to_be_bytes());
    sm3.update(distid);
    sm3.update(&SM2_EQUATION_A);
    sm3.update(&SM2_EQUATION_B);
    sm3.update(&SM2_GENERATOR_X);
    sm3.update(&SM2_GENERATOR_Y);
    sm3.update(public_key.x());
    sm3.update(public_key.y());
    Some(sm3.finalize())
}

impl<B: super::crypto_backend::CryptoBackend> Signature<B> {
    pub fn as_signature(&self) -> rasn_its::ieee1609dot2::base_types::Signature {
        use super::crypto_backend::Signature;
        match self {
            Self::P256(sig) => rasn_its::ieee1609dot2::base_types::Signature::EcdsaNistP256(
                rasn_its::ieee1609dot2::base_types::EcdsaP256Signature {
                    r_sig: rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::XOnly(
                        sig.r().into(),
                    ),
                    s_sig: sig.s().into(),
                },
            ),
            Self::P384(sig) => rasn_its::ieee1609dot2::base_types::Signature::EcdsaNistP384(
                rasn_its::ieee1609dot2::base_types::EcdsaP384Signature {
                    r_sig: rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::XOnly(
                        sig.r().into(),
                    ),
                    s_sig: sig.s().into(),
                },
            ),
            Self::BP256(sig) => {
                rasn_its::ieee1609dot2::base_types::Signature::EcdsaBrainpoolP256r1(
                    rasn_its::ieee1609dot2::base_types::EcdsaP256Signature {
                        r_sig: rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::XOnly(
                            sig.r().into(),
                        ),
                        s_sig: sig.s().into(),
                    },
                )
            }
            Self::BP384(sig) => {
                rasn_its::ieee1609dot2::base_types::Signature::EcdsaBrainpoolP384r1(
                    rasn_its::ieee1609dot2::base_types::EcdsaP384Signature {
                        r_sig: rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::XOnly(
                            sig.r().into(),
                        ),
                        s_sig: sig.s().into(),
                    },
                )
            }
            Self::SM2(sig) => rasn_its::ieee1609dot2::base_types::Signature::Sm2(
                rasn_its::ieee1609dot2::base_types::EcsigP256Signature {
                    r_sig: sig.r().into(),
                    s_sig: sig.s().into(),
                },
            ),
        }
    }

    pub fn parse(
        sig: &rasn_its::ieee1609dot2::base_types::Signature,
    ) -> Result<Self, &'static str> {
        use super::crypto_backend::Signature;
        use crypto_bigint::Encoding;
        const P256_ORDER: crypto_bigint::U256 = crypto_bigint::U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        const P384_ORDER: crypto_bigint::U384 = crypto_bigint::U384::from_be_hex("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973");
        const BP256_ORDER: crypto_bigint::U256 = crypto_bigint::U256::from_be_hex("a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7");
        const BP384_ORDER: crypto_bigint::U384 = crypto_bigint::U384::from_be_hex("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565");

        match sig {
            rasn_its::ieee1609dot2::base_types::Signature::EcdsaNistP256(sig) => {
                let r: [u8; 32] = match &sig.r_sig {
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::XOnly(r) => **r,
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY0(x)
                    | rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY1(x) => {
                        let x = crypto_bigint::U256::from_be_slice(&**x);
                        let (r, underflow) = x.borrowing_sub(&P256_ORDER, crypto_bigint::Limb::ZERO);
                        if (underflow.0 >> (crypto_bigint::Limb::BITS - 1)) as u8 == 0 {
                            x
                        } else {
                            r
                        }.to_bytes(crypto_bigint::ByteOrder::BigEndian).into()
                    }
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::Uncompressed(p) => {
                        let x = crypto_bigint::U256::from_be_slice(&*p.x);
                        let (r, underflow) = x.borrowing_sub(&P256_ORDER, crypto_bigint::Limb::ZERO);
                        if (underflow.0 >> (crypto_bigint::Limb::BITS - 1)) as u8 == 0 {
                            x
                        } else {
                            r
                        }.to_bytes(crypto_bigint::ByteOrder::BigEndian).into()
                    }
                    _ => return Err("invalid signature r encoding"),
                };
                let s: [u8; 32] = *sig.s_sig;
                Ok(Self::P256(
                    B::P256Signature::from_scalars(r, s).ok_or("invalid signature encoding")?
                ))
            }
            rasn_its::ieee1609dot2::base_types::Signature::EcdsaNistP384(sig) => {
                let r: [u8; 48] = match &sig.r_sig {
                    rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::XOnly(r) => **r,
                    rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::CompressedY0(x)
                    | rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::CompressedY1(x) => {
                        let x = crypto_bigint::U384::from_be_slice(&**x);
                        let (r, underflow) = x.borrowing_sub(&P384_ORDER, crypto_bigint::Limb::ZERO);
                        if (underflow.0 >> (crypto_bigint::Limb::BITS - 1)) as u8 == 0 {
                            x
                        } else {
                            r
                        }.to_bytes(crypto_bigint::ByteOrder::BigEndian).into()
                    }
                    rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::Uncompressed(p) => {
                        let x = crypto_bigint::U384::from_be_slice(&*p.x);
                        let (r, underflow) = x.borrowing_sub(&P384_ORDER, crypto_bigint::Limb::ZERO);
                        if (underflow.0 >> (crypto_bigint::Limb::BITS - 1)) as u8 == 0 {
                            x
                        } else {
                            r
                        }.to_bytes(crypto_bigint::ByteOrder::BigEndian).into()
                    }
                    _ => return Err("invalid signature r encoding"),
                };
                let s: [u8; 48] = *sig.s_sig;
                Ok(Self::P384(
                    B::P384Signature::from_scalars(r, s).ok_or("invalid signature encoding")?
                ))
            }
            rasn_its::ieee1609dot2::base_types::Signature::EcdsaBrainpoolP256r1(sig) => {
                let r: [u8; 32] = match &sig.r_sig {
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::XOnly(r) => **r,
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY0(x)
                    | rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY1(x) => {
                        let x = crypto_bigint::U256::from_be_slice(&**x);
                        let (r, underflow) = x.borrowing_sub(&BP256_ORDER, crypto_bigint::Limb::ZERO);
                        if (underflow.0 >> (crypto_bigint::Limb::BITS - 1)) as u8 == 0 {
                            x
                        } else {
                            r
                        }.to_bytes(crypto_bigint::ByteOrder::BigEndian).into()
                    }
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::Uncompressed(p) => {
                        let x = crypto_bigint::U256::from_be_slice(&*p.x);
                        let (r, underflow) = x.borrowing_sub(&BP256_ORDER, crypto_bigint::Limb::ZERO);
                        if (underflow.0 >> (crypto_bigint::Limb::BITS - 1)) as u8 == 0 {
                            x
                        } else {
                            r
                        }.to_bytes(crypto_bigint::ByteOrder::BigEndian).into()
                    }
                    _ => return Err("invalid signature r encoding"),
                };
                let s: [u8; 32] = *sig.s_sig;
                Ok(Self::BP256(
                    B::BP256Signature::from_scalars(r, s).ok_or("invalid signature encoding")?
                ))
            }
            rasn_its::ieee1609dot2::base_types::Signature::EcdsaBrainpoolP384r1(sig) => {
                let r: [u8; 48] = match &sig.r_sig {
                    rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::XOnly(r) => **r,
                    rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::CompressedY0(x)
                    | rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::CompressedY1(x) => {
                        let x = crypto_bigint::U384::from_be_slice(&**x);
                        let (r, underflow) = x.borrowing_sub(&BP384_ORDER, crypto_bigint::Limb::ZERO);
                        if (underflow.0 >> (crypto_bigint::Limb::BITS - 1)) as u8 == 0 {
                            x
                        } else {
                            r
                        }.to_bytes(crypto_bigint::ByteOrder::BigEndian).into()
                    }
                    rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::Uncompressed(p) => {
                        let x = crypto_bigint::U384::from_be_slice(&*p.x);
                        let (r, underflow) = x.borrowing_sub(&BP384_ORDER, crypto_bigint::Limb::ZERO);
                        if (underflow.0 >> (crypto_bigint::Limb::BITS - 1)) as u8 == 0 {
                            x
                        } else {
                            r
                        }.to_bytes(crypto_bigint::ByteOrder::BigEndian).into()
                    }
                    _ => return Err("invalid signature r encoding"),
                };
                let s: [u8; 48] = *sig.s_sig;
                Ok(Self::BP384(
                    B::BP384Signature::from_scalars(r, s).ok_or("invalid signature encoding")?
                ))
            }
            rasn_its::ieee1609dot2::base_types::Signature::Sm2(sig) => {
                let r: [u8; 32] = *sig.r_sig;
                let s: [u8; 32] = *sig.s_sig;
                Ok(Self::SM2(
                    B::SM2Signature::from_scalars(r, s).ok_or("invalid signature encoding")?
                ))
            }
            _ => Err("unsupported signature type"),
        }
    }

    pub(crate) fn verify(
        &self,
        public_key: &PublicKey<B>,
        hash: HashAlgorithm,
        tbs_bytes: &[u8],
        certificate: Option<&super::certs::CertificateReport<B>>,
    ) -> bool {

        let signer_info = match certificate {
            Some(c) => c.encoded(),
            None => &[],
        };
        let pre_hashed = match hash {
            HashAlgorithm::Sha256 => {
                let mut h = sha2::Sha256::new();
                h.update(sha2::Sha256::digest(tbs_bytes).as_slice());
                h.update(sha2::Sha256::digest(signer_info).as_slice());
                h.finalize().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut h = sha2::Sha384::new();
                h.update(sha2::Sha384::digest(tbs_bytes).as_slice());
                h.update(sha2::Sha384::digest(signer_info).as_slice());
                h.finalize().to_vec()
            }
            HashAlgorithm::Sm3 => {
                let PublicKey::SM2(pk) = public_key else {
                    return false;
                };
                let h = sm3::Sm3::digest(signer_info);
                let Some(z) = sm2_hash_z::<B>(
                    if certificate.is_some() {
                        h.as_slice()
                    } else {
                        b"1234567812345678"
                    },
                    pk,
                ) else {
                    return false;
                };
                sm3::Sm3::new_with_prefix(z)
                    .chain_update(tbs_bytes)
                    .finalize()
                    .to_vec()
            }
        };

        match (self, public_key) {
            (Self::P256(sig), PublicKey::P256(pk)) => {
                use super::crypto_backend::PublicKey;
                pk.verify_prehashed(&pre_hashed, sig)
            },
            (Self::BP256(sig), PublicKey::BP256(pk)) => {
                use super::crypto_backend::PublicKey;
                pk.verify_prehashed(&pre_hashed, sig)
            },
            (Self::P384(sig), PublicKey::P384(pk)) => {
                use super::crypto_backend::PublicKey;
                pk.verify_prehashed(&pre_hashed, sig)
            },
            (Self::BP384(sig), PublicKey::BP384(pk)) => {
                use super::crypto_backend::PublicKey;
                pk.verify_prehashed(&pre_hashed, sig)
            },
            (Self::SM2(sig), PublicKey::SM2(pk)) => {
                use super::crypto_backend::PublicKey;
                pk.verify_prehashed(&pre_hashed, sig)
            },
            _ => false,
        }
    }
}
