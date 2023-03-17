
use std::marker::PhantomData;

use ecc::{GeneralEccChip, EccConfig, integer::{IntegerInstructions, Range}};
use ecdsa::ecdsa::{EcdsaChip, AssignedEcdsaSig, AssignedPublicKey};
use halo2_proofs::{halo2curves::{CurveAffine, FieldExt}, plonk::{ConstraintSystem, Error, Circuit}, circuit::{Layouter, Value, SimpleFloorPlanner}};
use maingate::{MainGate, MainGateConfig, RangeChip, RangeConfig, RangeInstructions, RegionCtx};

const BIT_LEN_LIMB: usize = 68;
const NUMBER_OF_LIMBS: usize = 4;


#[derive(Clone, Debug)]
pub(crate) struct Spec256k1Gadget {

}

impl Spec256k1Gadget {
    pub fn configure<Fp: FieldExt>(
        meta: &mut ConstraintSystem<Fp>,
    ) -> Self {
        Self {

        }
    }

    pub fn verify_sig() {
        
    }
}

#[derive(Clone, Debug)]
struct CircuitEcdsaVerifyConfig {
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
}

impl CircuitEcdsaVerifyConfig {
    pub fn new<C: CurveAffine, N: FieldExt>(meta: &mut ConstraintSystem<N>) -> Self {
        let (rns_base, rns_scalar) =
            GeneralEccChip::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();
        let main_gate_config = MainGate::<N>::configure(meta);
        let mut overflow_bit_lens: Vec<usize> = vec![];
        overflow_bit_lens.extend(rns_base.overflow_lengths());
        overflow_bit_lens.extend(rns_scalar.overflow_lengths());
        let composition_bit_lens = vec![BIT_LEN_LIMB / NUMBER_OF_LIMBS];

        let range_config = RangeChip::<N>::configure(
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );
        CircuitEcdsaVerifyConfig {
            main_gate_config,
            range_config,
        }
    }

    pub fn ecc_chip_config(&self) -> EccConfig {
        EccConfig::new(self.range_config.clone(), self.main_gate_config.clone())
    }

    pub fn config_range<N: FieldExt>(
        &self,
        layouter: &mut impl Layouter<N>,
    ) -> Result<(), Error> {
        let range_chip = RangeChip::<N>::new(self.range_config.clone());
        range_chip.load_table(layouter)?;

        Ok(())
    }
}

#[derive(Default, Clone)]
struct CircuitEcdsaVerify<E: CurveAffine, N: FieldExt> {
    public_key: Value<E>,
    signature: Value<(E::Scalar, E::Scalar)>,
    msg_hash: Value<E::Scalar>,

    aux_generator: E,
    window_size: usize,
    _marker: PhantomData<N>,
}

impl<E: CurveAffine, N: FieldExt> Circuit<N> for CircuitEcdsaVerify<E, N> {
    type Config = CircuitEcdsaVerifyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
        CircuitEcdsaVerifyConfig::new::<E, N>(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<N>,
    ) -> Result<(), Error> {
        let mut ecc_chip = GeneralEccChip::<E, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(
            config.ecc_chip_config(),
        );

        layouter.assign_region(
            || "assign aux values",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                ecc_chip.assign_aux_generator(ctx, Value::known(self.aux_generator))?;
                ecc_chip.assign_aux(ctx, self.window_size, 1)?;
                Ok(())
            },
        )?;

        let ecdsa_chip = EcdsaChip::new(ecc_chip.clone());
        let scalar_chip = ecc_chip.scalar_field_chip();

        layouter.assign_region(
            || "region 0",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let r = self.signature.map(|signature| signature.0);
                let s = self.signature.map(|signature| signature.1);
                let integer_r = ecc_chip.new_unassigned_scalar(r);
                let integer_s = ecc_chip.new_unassigned_scalar(s);
                let msg_hash = ecc_chip.new_unassigned_scalar(self.msg_hash);

                let r_assigned =
                    scalar_chip.assign_integer(ctx, integer_r, Range::Remainder)?;
                let s_assigned =
                    scalar_chip.assign_integer(ctx, integer_s, Range::Remainder)?;
                let sig = AssignedEcdsaSig {
                    r: r_assigned,
                    s: s_assigned,
                };

                let pk_in_circuit = ecc_chip.assign_point(ctx, self.public_key)?;
                let pk_assigned = AssignedPublicKey {
                    point: pk_in_circuit,
                };
                let msg_hash = scalar_chip.assign_integer(ctx, msg_hash, Range::Remainder)?;
                ecdsa_chip.verify(ctx, &sig, &pk_assigned, &msg_hash)
            },
        )?;

        config.config_range(&mut layouter)?;

        Ok(())
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use halo2_proofs::{arithmetic::{CurveAffine, FieldExt, Field}, circuit::Value};
    use maingate::{fe_to_big, big_to_fe, mock_prover_verify};
    use rand::{rngs::OsRng, thread_rng};
    use halo2_proofs::halo2curves::group::{Curve, Group};
    // use crate::{test_utils::{Fp}};
    use halo2_proofs::halo2curves::secp256k1::Fp;

    use crate::gadgets::ecsdsa::CircuitEcdsaVerify;
    use ethers::{
        signers::{LocalWallet, Signer, Wallet}, 
        prelude::k256::{ecdsa::SigningKey},
        utils::hash_message
    };
    use k256::{
        ProjectivePoint, Scalar, elliptic_curve::{PrimeField, ops::MulByGenerator}
    };
    use hex_literal::hex;

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
      }

    #[test]
    fn test_affine() {
        Fp::from(1);
    }

    #[actix::test]
    async fn test_signature() {
        // let wallet = LocalWallet::new(&mut thread_rng());

        let wallet: Wallet<SigningKey> =
            "0000000000000000000000000000000000000000000000000000000000000001".parse().unwrap();
        println!("wallet address {:?}", wallet.address());

        // Declare the message you want to sign.
        let message = "Some data";

        // sign message from your wallet and print out signature produced.
        let signature = wallet.sign_message(message).await.unwrap();
        println!("Produced signature {signature} R: {0} S: {1}", signature.r, signature.s);
        let hash = hash_message(message);
        println!("Produced hash {:?}", hash);

        // verify the signature produced from your wallet.
        signature.verify(message, wallet.address()).unwrap();
        println!("Verified signature produced by {:?}!", wallet.address());
        let signer = wallet.signer();

        let (R, S, HASH)= (signature.r, signature.s, hash_message(message), );
        println!("signatrue data R: {R} S: {S} HASH: {HASH:?}");

    }

    
   

    #[test]
    fn test_ecdsa_verifier() {
        fn mod_n<C: CurveAffine>(x: C::Base) -> C::Scalar {
            let x_big = fe_to_big(x);
            big_to_fe(x_big)
        }

        fn run<C: CurveAffine, N: FieldExt>() {
            let g = C::generator();

            // Generate a key pair
            let sk = <C as CurveAffine>::ScalarExt::random(OsRng);
            println!("sk {sk:?}");

            // let sk_str = hex!("AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522");
            // let s = Scalar::from_repr(sk_str.into()).unwrap();
            // let sk = ProjectivePoint::mul_by_generator(&s);
            // let sk = <C as CurveAffine>::ScalarExt::mul_by_generator(s);
            let public_key = (g * sk).to_affine();

            // Generate a valid signature
            // Suppose `m_hash` is the message hash
            let msg_hash = <C as CurveAffine>::ScalarExt::random(OsRng);
            // 0x1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655
            // let msg_hash = <C as CurveAffine>::ScalarExt::from();
            println!("msg_hash {:?}", msg_hash);

            // Draw arandomness
            let k = <C as CurveAffine>::ScalarExt::random(OsRng);
            let k_inv = k.invert().unwrap();

            // Calculate `r`
            let r_point = (g * k).to_affine().coordinates().unwrap();
            let x = r_point.x();
            let r = mod_n::<C>(*x);

            // Calculate `s`
            let s = k_inv * (msg_hash + (r * sk));

            // Sanity check. Ensure we construct a valid signature. So lets verify it
            {
                let s_inv = s.invert().unwrap();
                let u_1 = msg_hash * s_inv;
                let u_2 = r * s_inv;
                let r_point = ((g * u_1) + (public_key * u_2))
                    .to_affine()
                    .coordinates()
                    .unwrap();
                let x_candidate = r_point.x();
                let r_candidate = mod_n::<C>(*x_candidate);
                assert_eq!(r, r_candidate);
            }

            let aux_generator = C::CurveExt::random(OsRng).to_affine();
            let circuit = CircuitEcdsaVerify::<C, N> {
                public_key: Value::known(public_key),
                signature: Value::known((r, s)),
                msg_hash: Value::known(msg_hash),
                aux_generator,
                window_size: 2,
                ..Default::default()
            };
            let instance = vec![vec![]];
            mock_prover_verify(&circuit, instance);
        }

        use halo2_proofs::halo2curves::bn256::Fr as BnScalar;
        use halo2_proofs::halo2curves::pasta::{Fp as PastaFp, Fq as PastaFq};
        use halo2_proofs::halo2curves::secp256k1::Secp256k1Affine;
        run::<Secp256k1Affine, BnScalar>();
        // run::<Secp256k1Affine, PastaFp>();
        // run::<Secp256k1Affine, PastaFq>();
    }
}