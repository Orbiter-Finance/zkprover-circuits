use halo2_proofs::{
    circuit::Value,
    halo2curves::{bn256::Fr, CurveAffine},
};

/// Configures a structure for the secret key.
#[derive(Clone, Debug)]
pub struct SecretKey(Fr);

impl SecretKey {}

/// Configures a structure for the public key.
#[derive(Hash, Clone, PartialEq, Eq, Default, Debug)]
pub struct PublicKey();

pub struct Signature<E: CurveAffine> {
    pub R: Value<E::Scalar>,
    pub S: Value<E::Scalar>,
    pub V: Value<E::Scalar>,
    pub PUB_KEY: Value<E::Scalar>,
}

impl<E: CurveAffine> Signature<E> {
    /// TODO: from MetaMask raw signature
    pub fn new(sig: Vec<u8>) -> Self {
        Signature {
            R: Default::default(),
            S: Default::default(),
            V: Default::default(),
            PUB_KEY: Default::default(),
        }
    }
}
