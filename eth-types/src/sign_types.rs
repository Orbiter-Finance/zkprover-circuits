use halo2_proofs::{
    arithmetic::{CurveAffine, FieldExt},
    halo2curves::{
        group::{
            ff::{Field as GroupField, PrimeField},
            Curve,
        },
        secp256k1::{self, Secp256k1Affine},
        Coordinates,
    },
};

use lazy_static::lazy_static;

/// Signature data required by the SignVerify Chip as input to verify a
/// signature.
#[derive(Clone, Debug)]
pub struct SignData {
    /// Secp256k1 signature point
    pub signature: (secp256k1::Fq, secp256k1::Fq),
    /// Secp256k1 public key
    pub pk: Secp256k1Affine,
    /// Hash of the message that is being signed
    pub msg_hash: secp256k1::Fq,
}

lazy_static! {
    static ref SIGN_DATA_DEFAULT: SignData = {
        let generator = Secp256k1Affine::generator();
        let sk = secp256k1::Fq::one();
        let pk = generator * sk;
        let pk = pk.to_affine();
        let msg_hash = secp256k1::Fq::one();
        let randomness = secp256k1::Fq::one();
        let (sig_r, sig_s) = sign(randomness, sk, msg_hash);

        SignData {
            signature: (sig_r, sig_s),
            pk,
            msg_hash,
        }
    };
}

impl Default for SignData {
    fn default() -> Self {
        // Hardcoded valid signature corresponding to a hardcoded private key and
        // message hash generated from "nothing up my sleeve" values to make the
        // ECDSA chip pass the constraints, to be use for padding signature
        // verifications (where the constraints pass, but we don't care about the
        // message hash and public key).
        SIGN_DATA_DEFAULT.clone()
    }
}

/// Return a copy of the serialized public key with swapped Endianness.
pub fn pk_bytes_swap_endianness<T: Clone>(pk: &[T]) -> [T; 64] {
    assert_eq!(pk.len(), 64);
    let mut pk_swap = <&[T; 64]>::try_from(pk)
        .map(|r| r.clone())
        .expect("pk.len() != 64");
    pk_swap[..32].reverse();
    pk_swap[32..].reverse();
    pk_swap
}

/// Return the secp256k1 public key (x, y) coordinates in little endian bytes.
pub fn pk_bytes_le(pk: &Secp256k1Affine) -> [u8; 64] {
    let pk_coord = Option::<Coordinates<_>>::from(pk.coordinates()).expect("point is the identity");
    let mut pk_le = [0u8; 64];
    pk_le[..32].copy_from_slice(&pk_coord.x().to_bytes());
    pk_le[32..].copy_from_slice(&pk_coord.y().to_bytes());
    pk_le
}

/// Do a secp256k1 signature with a given randomness value.
pub fn sign(
    randomness: secp256k1::Fq,
    sk: secp256k1::Fq,
    msg_hash: secp256k1::Fq,
) -> (secp256k1::Fq, secp256k1::Fq) {
    let randomness_inv =
        Option::<secp256k1::Fq>::from(randomness.invert()).expect("cannot invert randomness");
    let generator = Secp256k1Affine::generator();
    let sig_point = generator * randomness;
    let x = *Option::<Coordinates<_>>::from(sig_point.to_affine().coordinates())
        .expect("point is the identity")
        .x();

    let x_repr = &mut vec![0u8; 32];
    x_repr.copy_from_slice(x.to_bytes().as_slice());

    let mut x_bytes = [0u8; 64];
    x_bytes[..32].copy_from_slice(&x_repr[..]);

    let sig_r = secp256k1::Fq::from_bytes_wide(&x_bytes); // get x cordinate (E::Base) on E::Scalar
    let sig_s = randomness_inv * (msg_hash + sig_r * sk);
    (sig_r, sig_s)
}
