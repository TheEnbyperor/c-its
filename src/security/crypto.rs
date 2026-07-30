use ecdsa::signature::digest::Digest;
use elliptic_curve::sec1::ToSec1Point;
use serde::ser::SerializeStruct;

#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum HashAlgorithm {
    #[serde(rename = "sha256")]
    Sha256,
    #[serde(rename = "sha384")]
    Sha384,
    #[serde(rename = "sm3")]
    Sm3
}

impl TryFrom<&rasn_its::ieee1609dot2::base_types::HashAlgorithm> for HashAlgorithm {
    type Error = &'static str;

    fn try_from(value: &rasn_its::ieee1609dot2::base_types::HashAlgorithm) -> Result<Self, Self::Error> {
        match value {
            rasn_its::ieee1609dot2::base_types::HashAlgorithm::Sha256 => Ok(Self::Sha256),
            rasn_its::ieee1609dot2::base_types::HashAlgorithm::Sha384 => Ok(Self::Sha384),
            rasn_its::ieee1609dot2::base_types::HashAlgorithm::Sm3 => Ok(Self::Sm3),
            _ => Err("unknown hash algorithm")
        }
    }
}

impl TryFrom<rasn_its::ieee1609dot2::base_types::HashAlgorithm> for HashAlgorithm {
    type Error = &'static str;

    fn try_from(value: rasn_its::ieee1609dot2::base_types::HashAlgorithm) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

#[derive(Debug, Clone)]
pub enum PublicKey {
    P256(ecdsa::VerifyingKey<p256::NistP256>),
    P384(ecdsa::VerifyingKey<p384::NistP384>),
    BP256(ecdsa::VerifyingKey<bp256::r1::BrainpoolP256r1>),
    BP384(ecdsa::VerifyingKey<bp384::r1::BrainpoolP384r1>),
    SM2(sm2::dsa::VerifyingKey),
}

fn parse_p256_curve_point(key: &rasn_its::ieee1609dot2::base_types::EccP256CurvePoint) -> Result<p256::Sec1Point, &'static str> {
    Ok(match key {
        rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY0(point) => {
            let mut v = [0u8; 33];
            v[0] = sec1::point::Tag::CompressedEvenY as u8;
            v[1..].copy_from_slice(point.as_ref());
            p256::Sec1Point::from_bytes(&v).map_err(|_| "invalid curve point")?
        }
        rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY1(point) => {
            let mut v = [0u8; 33];
            v[0] = sec1::point::Tag::CompressedOddY as u8;
            v[1..].copy_from_slice(point.as_ref());
            p256::Sec1Point::from_bytes(&v).map_err(|_| "invalid curve point")?
        }
        rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::Uncompressed(point) => {
            let mut v = [0u8; 65];
            v[0] = sec1::point::Tag::Uncompressed as u8;
            v[1..33].copy_from_slice(point.x.as_ref());
            v[33..65].copy_from_slice(point.y.as_ref());
            p256::Sec1Point::from_bytes(&v).map_err(|_| "invalid curve point")?
        },
        _ => return Err("invalid curve point"),
    })
}

fn parse_bp256_r1_curve_point(key: &rasn_its::ieee1609dot2::base_types::EccP256CurvePoint) -> Result<bp256::r1::Sec1Point, &'static str> {
    Ok(match key {
        rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY0(point) => {
            let mut v = [0u8; 33];
            v[0] = sec1::point::Tag::CompressedEvenY as u8;
            v[1..].copy_from_slice(point.as_ref());
            bp256::r1::Sec1Point::from_bytes(&v).map_err(|_| "invalid curve point")?
        }
        rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY1(point) => {
            let mut v = [0u8; 33];
            v[0] = sec1::point::Tag::CompressedOddY as u8;
            v[1..].copy_from_slice(point.as_ref());
            bp256::r1::Sec1Point::from_bytes(&v).map_err(|_| "invalid curve point")?
        }
        rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::Uncompressed(point) => {
            let mut v = [0u8; 65];
            v[0] = sec1::point::Tag::Uncompressed as u8;
            v[1..33].copy_from_slice(point.x.as_ref());
            v[33..65].copy_from_slice(point.y.as_ref());
            bp256::r1::Sec1Point::from_bytes(&v).map_err(|_| "invalid curve point")?
        },
        _ => return Err("invalid curve point"),
    })
}

fn parse_p384_curve_point(key: &rasn_its::ieee1609dot2::base_types::EccP384CurvePoint) -> Result<p384::Sec1Point, &'static str> {
    Ok(match key {
        rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::CompressedY0(point) => {
            let mut v = [0u8; 49];
            v[0] = sec1::point::Tag::CompressedEvenY as u8;
            v[1..].copy_from_slice(point.as_ref());
            p384::Sec1Point::from_bytes(&v).map_err(|_| "invalid curve point")?
        }
        rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::CompressedY1(point) => {
            let mut v = [0u8; 49];
            v[0] = sec1::point::Tag::CompressedOddY as u8;
            v[1..].copy_from_slice(point.as_ref());
            p384::Sec1Point::from_bytes(&v).map_err(|_| "invalid curve point")?
        }
        rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::Uncompressed(point) => {
            let mut v = [0u8; 97];
            v[0] = sec1::point::Tag::Uncompressed as u8;
            v[1..49].copy_from_slice(point.x.as_ref());
            v[49..97].copy_from_slice(point.y.as_ref());
            p384::Sec1Point::from_bytes(&v).map_err(|_| "invalid curve point")?
        },
        _ => return Err("invalid curve point"),
    })
}

fn parse_bp384_r1_curve_point(key: &rasn_its::ieee1609dot2::base_types::EccP384CurvePoint) -> Result<bp384::r1::Sec1Point, &'static str> {
    Ok(match key {
        rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::CompressedY0(point) => {
            let mut v = [0u8; 49];
            v[0] = sec1::point::Tag::CompressedEvenY as u8;
            v[1..].copy_from_slice(point.as_ref());
            bp384::r1::Sec1Point::from_bytes(&v).map_err(|_| "invalid curve point")?
        }
        rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::CompressedY1(point) => {
            let mut v = [0u8; 49];
            v[0] = sec1::point::Tag::CompressedOddY as u8;
            v[1..].copy_from_slice(point.as_ref());
            bp384::r1::Sec1Point::from_bytes(&v).map_err(|_| "invalid curve point")?
        }
        rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::Uncompressed(point) => {
            let mut v = [0u8; 97];
            v[0] = sec1::point::Tag::Uncompressed as u8;
            v[1..49].copy_from_slice(point.x.as_ref());
            v[49..97].copy_from_slice(point.y.as_ref());
            bp384::r1::Sec1Point::from_bytes(&v).map_err(|_| "invalid curve point")?
        },
        _ => return Err("invalid curve point"),
    })
}

impl PublicKey {
    pub(crate) fn parse(key: &rasn_its::ieee1609dot2::base_types::PublicVerificationKey) -> Result<Self, &'static str> {
        use elliptic_curve::sec1::FromSec1Point;
        match key {
            rasn_its::ieee1609dot2::base_types::PublicVerificationKey::EcdsaNistP256(key) => {
                let encoded_point = parse_p256_curve_point(key)?;
                Ok(Self::P256(p256::ecdsa::VerifyingKey::from_sec1_point(&encoded_point).map_err(|_| "invalid curve point")?))
            }
            rasn_its::ieee1609dot2::base_types::PublicVerificationKey::EcdsaBrainpoolP256r1(key) => {
                let encoded_point = parse_bp256_r1_curve_point(key)?;
                Ok(Self::BP256(ecdsa::VerifyingKey::from_sec1_point(&encoded_point).map_err(|_| "invalid curve point")?))
            }
            rasn_its::ieee1609dot2::base_types::PublicVerificationKey::EcdsaNistP384(key) => {
                let encoded_point = parse_p384_curve_point(key)?;
                Ok(Self::P384(p384::ecdsa::VerifyingKey::from_sec1_point(&encoded_point).map_err(|_| "invalid curve point")?))
            }
            rasn_its::ieee1609dot2::base_types::PublicVerificationKey::EcdsaBrainpoolP384r1(key) => {
                let encoded_point = parse_bp384_r1_curve_point(key)?;
                Ok(Self::BP384(ecdsa::VerifyingKey::from_sec1_point(&encoded_point).map_err(|_| "invalid curve point")?))
            }
            rasn_its::ieee1609dot2::base_types::PublicVerificationKey::EcsigSm2(key) => {
                let encoded_point = parse_p256_curve_point(key)?;
                let ap = sm2::AffinePoint::from_sec1_point(&encoded_point).into_option().ok_or("invalid curve point")?;
                Ok(Self::SM2(sm2::dsa::VerifyingKey::from_affine("", ap).map_err(|_| "invalid curve point")?))
            }
            _ => Err("unsupported public key type")
        }
    }
}

impl core::cmp::PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::P256(k1), Self::P256(k2)) => k1 == k2,
            (Self::P384(k1), Self::P384(k2)) => k1 == k2,
            (Self::BP256(k1), Self::BP256(k2)) => k1 == k2,
            (Self::BP384(k1), Self::BP384(k2)) => k1 == k2,
            (Self::SM2(k1), Self::SM2(k2)) => k1.as_ref() == k2.as_ref(),
            _ => false
        }
    }
}

impl core::cmp::Eq for PublicKey {}

impl core::cmp::PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        match (self, other) {
            (Self::P256(k1), Self::P256(k2)) => k1.partial_cmp(k2),
            (Self::P384(k1), Self::P384(k2)) => k1.partial_cmp(k2),
            (Self::BP256(k1), Self::BP256(k2)) => k1.partial_cmp(k2),
            (Self::BP384(k1), Self::BP384(k2)) => k1.partial_cmp(k2),
            (Self::SM2(k1), Self::SM2(k2)) => k1.to_sec1_point(false).partial_cmp(&k2.to_sec1_point(false)),
            _ => None
        }
    }
}

impl core::cmp::Ord for PublicKey {
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

impl serde::Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
        let mut struct_serializer = serializer.serialize_struct("PublicKey", 2)?;
        match self {
            Self::P256(k) => {
                struct_serializer.serialize_field("curve", "nistP256")?;
                struct_serializer.serialize_field("k", &hex::encode_upper(k.to_sec1_point(true).as_bytes()))?;
            }
            Self::P384(k) => {
                struct_serializer.serialize_field("curve", "nistP384")?;
                struct_serializer.serialize_field("k", &hex::encode_upper(k.to_sec1_point(true).as_bytes()))?;
            }
            Self::BP256(k) => {
                struct_serializer.serialize_field("curve", "brainpoolP256r1")?;
                struct_serializer.serialize_field("k", &hex::encode_upper(k.to_sec1_point(true).as_bytes()))?;
            }
            Self::BP384(k) => {
                struct_serializer.serialize_field("curve", "brainpoolP384r1")?;
                struct_serializer.serialize_field("k", &hex::encode_upper(k.to_sec1_point(true).as_bytes()))?;
            }
            Self::SM2(k) => {
                struct_serializer.serialize_field("curve", "sm2")?;
                struct_serializer.serialize_field("k", &hex::encode_upper(k.to_sec1_point(true).as_bytes()))?;
            }
        }
        struct_serializer.end()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Signature {
    P256(p256::ecdsa::Signature),
    P384(p384::ecdsa::Signature),
    BP256(bp256::r1::ecdsa::Signature),
    BP384(bp384::r1::ecdsa::Signature),
    SM2(sm2::dsa::Signature),
}

impl core::cmp::PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        match (self, other) {
            (Self::P256(s1), Self::P256(s2)) => match s1.r().cmp(&s2.r()) {
                core::cmp::Ordering::Less => Some(core::cmp::Ordering::Less),
                core::cmp::Ordering::Greater => Some(core::cmp::Ordering::Greater),
                core::cmp::Ordering::Equal => Some(s1.s().cmp(&s2.s())),
            }
            (Self::P384(s1), Self::P384(s2)) => match s1.r().cmp(&s2.r()) {
                core::cmp::Ordering::Less => Some(core::cmp::Ordering::Less),
                core::cmp::Ordering::Greater => Some(core::cmp::Ordering::Greater),
                core::cmp::Ordering::Equal => Some(s1.s().cmp(&s2.s())),
            }
            (Self::BP256(s1), Self::BP256(s2)) => match s1.r().cmp(&s2.r()) {
                core::cmp::Ordering::Less => Some(core::cmp::Ordering::Less),
                core::cmp::Ordering::Greater => Some(core::cmp::Ordering::Greater),
                core::cmp::Ordering::Equal => Some(s1.s().cmp(&s2.s())),
            }
            (Self::BP384(s1), Self::BP384(s2)) => match s1.r().cmp(&s2.r()) {
                core::cmp::Ordering::Less => Some(core::cmp::Ordering::Less),
                core::cmp::Ordering::Greater => Some(core::cmp::Ordering::Greater),
                core::cmp::Ordering::Equal => Some(s1.s().cmp(&s2.s())),
            }
            (Self::SM2(s1), Self::SM2(s2)) => match s1.r().cmp(&s2.r()) {
                core::cmp::Ordering::Less => Some(core::cmp::Ordering::Less),
                core::cmp::Ordering::Greater => Some(core::cmp::Ordering::Greater),
                core::cmp::Ordering::Equal => Some(s1.s().cmp(&s2.s())),
            }
            _ => None,
        }
    }
}

impl core::cmp::Ord for Signature {
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

fn sm2_hash_z(distid: &[u8], public_key: &impl AsRef<sm2::AffinePoint>) -> elliptic_curve::Result<sm3::digest::Output<sm3::Sm3>> {
    use primeorder::PrimeCurveParams;
    use elliptic_curve::sec1::ToSec1Point;

    let entla: u16 = distid
        .len()
        .checked_mul(8)
        .and_then(|l| l.try_into().ok())
        .ok_or(elliptic_curve::Error)?;

    let mut sm3 = sm3::Sm3::new();
    sm3.update(entla.to_be_bytes());
    sm3.update(distid);
    sm3.update(sm2::Sm2::EQUATION_A.to_bytes());
    sm3.update(sm2::Sm2::EQUATION_B.to_bytes());
    sm3.update(sm2::Sm2::GENERATOR.0.to_bytes());
    sm3.update(sm2::Sm2::GENERATOR.1.to_bytes());

    match public_key.as_ref().to_sec1_point(false).coordinates() {
        elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => {
            sm3.update(x);
            sm3.update(y);
            Ok(sm3.finalize())
        }
        _ => Err(elliptic_curve::Error),
    }
}

impl Signature {
    pub(crate) fn parse(sig: &rasn_its::ieee1609dot2::base_types::Signature) -> Result<Self, &'static str> {
        use p256::elliptic_curve::ops::Reduce;

        match sig {
            rasn_its::ieee1609dot2::base_types::Signature::EcdsaNistP256(sig) => {
                let r: [u8; 32] = match &sig.r_sig {
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::XOnly(r) => **r,
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY0(x) |
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY1(x) => {
                        let x: [u8; 32] = **x;
                        <p256::Scalar as Reduce<hybrid_array::Array<u8, _>>>::reduce(
                            &<hybrid_array::Array<_, _>>::into(<[u8; 32]>::into(x))).to_bytes().into()
                    },
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::Uncompressed(p) => {
                        let x: [u8; 32] = *p.x;
                        <p256::Scalar as Reduce<hybrid_array::Array<u8, _>>>::reduce(
                            &<hybrid_array::Array<_, _>>::into(<[u8; 32]>::into(x))).to_bytes().into()
                    },
                    _ => return Err("invalid signature r encoding")
                };
                let s: [u8; 32] = *sig.s_sig;
                Ok(Self::P256(p256::ecdsa::Signature::from_scalars(r, s, ).map_err(|_| "invalid signature encoding")?))
            },
            rasn_its::ieee1609dot2::base_types::Signature::EcdsaNistP384(sig) => {
                let r: [u8; 48] = match &sig.r_sig {
                    rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::XOnly(r) => **r,
                    rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::CompressedY0(x) |
                    rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::CompressedY1(x) => {
                        let x: [u8; 48] = **x;
                        <p384::Scalar as Reduce<hybrid_array::Array<u8, _>>>::reduce(
                            &<hybrid_array::Array<_, _>>::into(<[u8; 48]>::into(x))).to_bytes().into()
                    },
                    rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::Uncompressed(p) => {
                        let x: [u8; 48] = *p.x;
                        <p384::Scalar as Reduce<hybrid_array::Array<u8, _>>>::reduce(
                            &<hybrid_array::Array<_, _>>::into(<[u8; 48]>::into(x))).to_bytes().into()
                    },
                    _ => return Err("invalid signature r encoding")
                };
                let s: [u8; 48] = *sig.s_sig;
                Ok(Self::P384(p384::ecdsa::Signature::from_scalars(r, s).map_err(|_| "invalid signature encoding")?))
            }
            rasn_its::ieee1609dot2::base_types::Signature::EcdsaBrainpoolP256r1(sig) => {
                use crypto_bigint::Reduce;
                let r: [u8; 32] = match &sig.r_sig {
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::XOnly(r) => **r,
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY0(x) |
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::CompressedY1(x) => {
                        let x: [u8; 32] = **x;
                        <bp256::Scalar as Reduce<hybrid_array::Array<u8, _>>>::reduce(
                            &<hybrid_array::Array<_, _>>::into(<[u8; 32]>::into(x))).to_bytes().into()
                    },
                    rasn_its::ieee1609dot2::base_types::EccP256CurvePoint::Uncompressed(p) => {
                        let x: [u8; 32] = *p.x;
                        <bp256::Scalar as Reduce<hybrid_array::Array<u8, _>>>::reduce(
                            &<hybrid_array::Array<_, _>>::into(<[u8; 32]>::into(x))).to_bytes().into()
                    },
                    _ => return Err("invalid signature r encoding")
                };
                let s: [u8; 32] = *sig.s_sig;
                Ok(Self::BP256(bp256::r1::ecdsa::Signature::from_scalars(r, s).map_err(|_| "invalid signature encoding")?))
            }
            rasn_its::ieee1609dot2::base_types::Signature::EcdsaBrainpoolP384r1(sig) => {
                use crypto_bigint::Reduce;
                let r: [u8; 48] = match &sig.r_sig {
                    rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::XOnly(r) => **r,
                    rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::CompressedY0(x) |
                    rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::CompressedY1(x) => {
                        let x: [u8; 48] = **x;
                        <bp384::Scalar as Reduce<hybrid_array::Array<u8, _>>>::reduce(
                            &<hybrid_array::Array<_, _>>::into(<[u8; 48]>::into(x))).to_bytes().into()
                    },
                    rasn_its::ieee1609dot2::base_types::EccP384CurvePoint::Uncompressed(p) => {
                        let x: [u8; 48] = *p.x;
                        <bp384::Scalar as Reduce<hybrid_array::Array<u8, _>>>::reduce(
                            &<hybrid_array::Array<_, _>>::into(<[u8; 48]>::into(x))).to_bytes().into()
                    }
                    _ => return Err("invalid signature r encoding")
                };
                let s: [u8; 48] = *sig.s_sig;
                Ok(Self::BP384(bp384::r1::ecdsa::Signature::from_scalars(r, s).map_err(|_| "invalid signature encoding")?))
            }
            rasn_its::ieee1609dot2::base_types::Signature::Sm2(sig) => {
                let r: [u8; 32] = *sig.r_sig;
                let s: [u8; 32] = *sig.s_sig;
                Ok(Self::SM2(sm2::dsa::Signature::from_scalars(r, s).map_err(|_ | "invalid signature encoding")?))
            },
            _ => Err("unsupported signature type")
        }
    }

    pub(crate) fn verify(&self, public_key: &PublicKey, hash: HashAlgorithm, tbs_bytes: &[u8], certificate: Option<&super::certs::CertificateReport>) -> bool {
        use ecdsa::signature::hazmat::PrehashVerifier;

        let signer_info = match certificate {
            Some(c) => c.encoded(),
            None => &[]
        };
        let pre_hashed = match hash {
            HashAlgorithm::Sha256 => {
                let mut h = sha2::Sha256::new();
                h.update(sha2::Sha256::digest(tbs_bytes).as_slice());
                h.update(sha2::Sha256::digest(signer_info).as_slice());
                h.finalize().to_vec()
            },
            HashAlgorithm::Sha384 => {
                let mut h = sha2::Sha384::new();
                h.update(sha2::Sha384::digest(tbs_bytes).as_slice());
                h.update(sha2::Sha384::digest(signer_info).as_slice());
                h.finalize().to_vec()
            },
            HashAlgorithm::Sm3 => {
                let PublicKey::SM2(pk) = public_key else {
                    return false;
                };
                let h = sm3::Sm3::digest(signer_info);
                let Ok(z) = sm2_hash_z(if certificate.is_some() {
                    h.as_slice()
                } else {
                    b"1234567812345678"
                }, pk) else {
                    return false;
                };
                sm3::Sm3::new_with_prefix(z)
                    .chain_update(tbs_bytes)
                    .finalize().to_vec()
            }
        };

        match (self, public_key) {
            (Self::P256(sig), PublicKey::P256(pk)) => {
                pk.verify_prehash(&pre_hashed, sig).is_ok()
            },
            (Self::BP256(sig), PublicKey::BP256(pk)) => {
                pk.verify_prehash(&pre_hashed, sig).is_ok()
            },
            (Self::P384(sig), PublicKey::P384(pk)) => {
                pk.verify_prehash(&pre_hashed, sig).is_ok()
            },
            (Self::BP384(sig), PublicKey::BP384(pk)) => {
                pk.verify_prehash(&pre_hashed, sig).is_ok()
            },
            (Self::SM2(sig), PublicKey::SM2(pk)) => {
                pk.verify_prehash(&pre_hashed, sig).is_ok()
            },
            _ => false
        }
    }
}