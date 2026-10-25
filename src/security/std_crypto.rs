use ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use elliptic_curve::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use super::crypto_backend;

// Marker type only; the extra derives satisfy the `B: Trait` bounds that
// `#[derive]` puts on structs generic over the backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct StdCrypto {}

impl crypto_backend::CryptoBackend for StdCrypto {
    type P256PrivateKey = P256PrivateKey;
    type P256PublicKey = P256PublicKey;
    type P256Signature = P256Signature;

    type P384PrivateKey = P384PrivateKey;
    type P384PublicKey = P384PublicKey;
    type P384Signature = P384Signature;

    type BP256PrivateKey = BP256PrivateKey;
    type BP256PublicKey = BP256PublicKey;
    type BP256Signature = BP256Signature;

    type BP384PrivateKey = BP384PrivateKey;
    type BP384PublicKey = BP384PublicKey;
    type BP384Signature = BP384Signature;

    type SM2PrivateKey = SM2PrivateKey;
    type SM2PublicKey = SM2PublicKey;
    type SM2Signature = SM2Signature;
}

fn split_coordinates<const FIELD_SIZE: usize>(uncompressed_point: &[u8]) -> ([u8; FIELD_SIZE], [u8; FIELD_SIZE]) {
    let mut x = [0u8; FIELD_SIZE];
    let mut y = [0u8; FIELD_SIZE];
    x.copy_from_slice(&uncompressed_point[1..1 + FIELD_SIZE]);
    y.copy_from_slice(&uncompressed_point[1 + FIELD_SIZE..1 + 2 * FIELD_SIZE]);
    (x, y)
}

fn split_scalars<const FIELD_SIZE: usize>(sig_bytes: &[u8]) -> ([u8; FIELD_SIZE], [u8; FIELD_SIZE]) {
    let mut r = [0u8; FIELD_SIZE];
    let mut s = [0u8; FIELD_SIZE];
    r.copy_from_slice(&sig_bytes[..FIELD_SIZE]);
    s.copy_from_slice(&sig_bytes[FIELD_SIZE..2 * FIELD_SIZE]);
    (r, s)
}

macro_rules! ecdsa_curve {
    ($private:ident, $public:ident, $signature:ident, $curve:ty, $digest:ty, $field_size:literal) => {
        #[derive(Clone, Debug)]
        pub struct $private(ecdsa::SigningKey<$curve>);
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $public(ecdsa::VerifyingKey<$curve>);
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $signature(ecdsa::Signature<$curve>);

        impl $private {
            pub fn inner(&self) -> &ecdsa::SigningKey<$curve> {
                &self.0
            }
        }

        impl From<ecdsa::SigningKey<$curve>> for $private {
            fn from(key: ecdsa::SigningKey<$curve>) -> Self {
                Self(key)
            }
        }

        impl crypto_backend::PrivateKey<$public, $signature> for $private {
            fn public_key(&self) -> $public {
                $public(self.0.verifying_key().clone())
            }

            fn sign_prehashed(&self, hash: &[u8]) -> Option<$signature> {
                let (s, _) = ecdsa::hazmat::sign_prehashed_rfc6979::<$curve, $digest>(
                    self.0.as_nonzero_scalar(),
                    hash,
                    &[],
                );
                Some($signature(s))
            }

            fn from_pkcs8_der(der: &[u8]) -> Option<Self>
            where
                Self: Sized
            {
                ecdsa::SigningKey::<$curve>::from_pkcs8_der(der).ok().map($private)
            }

            fn to_pkcs8_der(&self) -> Option<alloc::vec::Vec<u8>> {
                Some(self.0.to_pkcs8_der().ok()?.as_bytes().to_vec())
            }
        }

        impl $public {
            pub fn inner(&self) -> &ecdsa::VerifyingKey<$curve> {
                &self.0
            }
        }

        impl crypto_backend::PublicKey<$field_size, $signature> for $public {
            fn x(&self) -> [u8; $field_size] {
                split_coordinates::<$field_size>(self.0.to_sec1_point(false).as_bytes()).0
            }

            fn y(&self) -> [u8; $field_size] {
                split_coordinates::<$field_size>(self.0.to_sec1_point(false).as_bytes()).1
            }

            fn even_y(&self) -> bool {
                self.y()[$field_size - 1] & 1 == 0
            }

            fn verify_prehashed(&self, hash: &[u8], sig: &$signature) -> bool {
                self.0.verify_prehash(hash, &sig.0).is_ok()
            }

            fn from_sec1_point(point: &[u8]) -> Option<Self>
            where
                Self: Sized
            {
                ecdsa::VerifyingKey::<$curve>::from_sec1_bytes(point).ok().map($public)
            }
        }

        impl crypto_backend::Signature<$field_size> for $signature {
            fn r(&self) -> [u8; $field_size] {
                split_scalars::<$field_size>(&self.0.to_bytes()).0
            }

            fn s(&self) -> [u8; $field_size] {
                split_scalars::<$field_size>(&self.0.to_bytes()).1
            }

            fn from_scalars(r: [u8; $field_size], s: [u8; $field_size]) -> Option<Self>
            where
                Self: Sized
            {
                ecdsa::Signature::<$curve>::from_scalars(r, s).ok().map($signature)
            }
        }
    };
}

ecdsa_curve!(P256PrivateKey, P256PublicKey, P256Signature, p256::NistP256, sha2::Sha256, 32);
ecdsa_curve!(P384PrivateKey, P384PublicKey, P384Signature, p384::NistP384, sha2::Sha384, 48);
ecdsa_curve!(BP256PrivateKey, BP256PublicKey, BP256Signature, bp256::r1::BrainpoolP256r1, sha2::Sha256, 32);
ecdsa_curve!(BP384PrivateKey, BP384PublicKey, BP384Signature, bp384::r1::BrainpoolP384r1, sha2::Sha384, 48);

#[derive(Clone, Debug)]
pub struct SM2PrivateKey(sm2::dsa::SigningKey);
#[derive(Clone, Debug)]
pub struct SM2PublicKey(sm2::dsa::VerifyingKey);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SM2Signature(sm2::dsa::Signature);

impl SM2PrivateKey {
    pub fn inner(&self) -> &sm2::dsa::SigningKey {
        &self.0
    }
}

impl From<sm2::dsa::SigningKey> for SM2PrivateKey {
    fn from(key: sm2::dsa::SigningKey) -> Self {
        Self(key)
    }
}

impl crypto_backend::PrivateKey<SM2PublicKey, SM2Signature> for SM2PrivateKey {
    fn public_key(&self) -> SM2PublicKey {
        SM2PublicKey(self.0.verifying_key().clone())
    }

    fn sign_prehashed(&self, hash: &[u8]) -> Option<SM2Signature> {
        Some(SM2Signature(self.0.sign_prehash(hash).ok()?))
    }

    fn from_pkcs8_der(der: &[u8]) -> Option<Self>
    where
        Self: Sized
    {
        let key = sm2::SecretKey::from_pkcs8_der(der).ok()?;
        sm2::dsa::SigningKey::from_nonzero_scalar("", key.to_nonzero_scalar()).ok().map(SM2PrivateKey)
    }

    fn to_pkcs8_der(&self) -> Option<alloc::vec::Vec<u8>> {
        let key = sm2::SecretKey::from(self.0.as_nonzero_scalar());
        Some(key.to_pkcs8_der().ok()?.as_bytes().to_vec())
    }
}

impl SM2PublicKey {
    pub fn inner(&self) -> &sm2::dsa::VerifyingKey {
        &self.0
    }

    fn uncompressed(&self) -> alloc::boxed::Box<[u8]> {
        use elliptic_curve::sec1::ToSec1Point;
        self.0.to_sec1_point(false).as_bytes().into()
    }
}

impl PartialEq for SM2PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_affine() == other.0.as_affine()
    }
}

impl Eq for SM2PublicKey {}

impl PartialOrd for SM2PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SM2PublicKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.uncompressed().cmp(&other.uncompressed())
    }
}

impl crypto_backend::PublicKey<32, SM2Signature> for SM2PublicKey {
    fn x(&self) -> [u8; 32] {
        split_coordinates::<32>(&self.uncompressed()).0
    }

    fn y(&self) -> [u8; 32] {
        split_coordinates::<32>(&self.uncompressed()).1
    }

    fn even_y(&self) -> bool {
        self.y()[31] & 1 == 0
    }

    fn verify_prehashed(&self, hash: &[u8], sig: &SM2Signature) -> bool {
        self.0.verify_prehash(hash, &sig.0).is_ok()
    }

    fn from_sec1_point(point: &[u8]) -> Option<Self>
    where
        Self: Sized
    {
        sm2::dsa::VerifyingKey::from_sec1_bytes("", point).ok().map(SM2PublicKey)
    }
}

impl crypto_backend::Signature<32> for SM2Signature {
    fn r(&self) -> [u8; 32] {
        split_scalars::<32>(&self.0.to_bytes()).0
    }

    fn s(&self) -> [u8; 32] {
        split_scalars::<32>(&self.0.to_bytes()).1
    }

    fn from_scalars(r: [u8; 32], s: [u8; 32]) -> Option<Self>
    where
        Self: Sized
    {
        sm2::dsa::Signature::from_scalars(r, s).ok().map(SM2Signature)
    }
}

