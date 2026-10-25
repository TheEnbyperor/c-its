use core::fmt::Debug;

pub trait CryptoBackend: Clone {
    type P256PrivateKey: PrivateKey<Self::P256PublicKey, Self::P256Signature>;
    type P256PublicKey: PublicKey<32, Self::P256Signature>;
    type P256Signature: Signature<32>;

    type P384PrivateKey: PrivateKey<Self::P384PublicKey, Self::P384Signature>;
    type P384PublicKey: PublicKey<48, Self::P384Signature>;
    type P384Signature: Signature<48>;
    
    type BP256PrivateKey: PrivateKey<Self::BP256PublicKey, Self::BP256Signature>;
    type BP256PublicKey: PublicKey<32, Self::BP256Signature>;
    type BP256Signature: Signature<32>;
    
    type BP384PrivateKey: PrivateKey<Self::BP384PublicKey, Self::BP384Signature>;
    type BP384PublicKey: PublicKey<48, Self::BP384Signature>;
    type BP384Signature: Signature<48>;
    
    type SM2PrivateKey: PrivateKey<Self::SM2PublicKey, Self::SM2Signature>;
    type SM2PublicKey: PublicKey<32, Self::SM2Signature>;
    type SM2Signature: Signature<32>;
}

pub trait PrivateKey<PublicKey, Signature> {
    fn public_key(&self) -> PublicKey;
    fn sign_prehashed(&self, hash: &[u8]) -> Option<Signature>;
    fn from_pkcs8_der(der: &[u8]) -> Option<Self> where Self: Sized;
    fn to_pkcs8_der(&self) -> Option<alloc::vec::Vec<u8>>;
}

pub trait PublicKey<const FIELD_SIZE: usize, Signature>: PartialEq + Eq + PartialOrd + Ord + Clone + Debug {
    fn x(&self) -> [u8; FIELD_SIZE];
    fn y(&self) -> [u8; FIELD_SIZE];
    fn even_y(&self) -> bool;

    fn verify_prehashed(&self, hash: &[u8], sig: &Signature) -> bool;
    fn from_sec1_point(point: &[u8]) -> Option<Self> where Self: Sized;
}

pub trait Signature<const FIELD_SIZE: usize>: PartialEq + Eq + Clone + Debug {
    fn r(&self) -> [u8; FIELD_SIZE];
    fn s(&self) -> [u8; FIELD_SIZE];
    fn from_scalars(r: [u8; FIELD_SIZE], s: [u8; FIELD_SIZE]) -> Option<Self> where Self: Sized;
}