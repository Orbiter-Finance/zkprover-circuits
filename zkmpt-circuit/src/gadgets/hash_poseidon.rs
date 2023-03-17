use halo2_gadgets::poseidon::{primitives::{Spec, Domain, Hash, P128Pow5T3}};
use halo2_proofs::halo2curves::{FieldExt, bn256::Fr};


pub trait Hashable: FieldExt {
    /// the spec type used in circuit for this hashable field
    type SpecType: Spec<Self, 3, 2>;
    /// the domain type used for hash calculation
    type DomainType: Domain<Self, 2>;

    /// execute hash for any sequence of fields
    fn hash(inp: [Self; 2]) -> Self;
    /// obtain the rows consumed by each circuit block
    fn hash_block_size() -> usize {
        1 + Self::SpecType::full_rounds() + (Self::SpecType::partial_rounds() + 1) / 2
    }
    /// init a hasher used for hash
    fn hasher() -> Hash<Self, Self::SpecType, Self::DomainType, 3, 2> {
        Hash::<Self, Self::SpecType, Self::DomainType, 3, 2>::init()
    }
}

// impl Hashable for Fr {
    
//     type SpecType = P128Pow5T3;
//     type DomainType = ConstantLengthIden3<2>;
//     fn hash(inp: [Self; 2]) -> Self {
//         Self::hasher().hash(inp)
//     }

// }

#[cfg(test)]
mod tests {
    use halo2_gadgets::poseidon::{
        primitives::{Spec, self as poseidon, ConstantLength}
    };
    use halo2_proofs::arithmetic::Field;
    use crate::test_utils::Fp;
    #[derive(Debug, Clone, Copy)]
    struct MySpec<const WIDTH: usize, const RATE: usize>;

    impl<const WIDTH: usize, const RATE: usize> Spec<Fp, WIDTH, RATE> for MySpec<WIDTH, RATE> {
        fn full_rounds() -> usize {
            8
        }

        fn partial_rounds() -> usize {
            56
        }

        fn sbox(val: Fp) -> Fp {
            val.pow_vartime(&[5])
        }

        fn secure_mds() -> usize {
            0
        }
    }

    #[test]
    fn test_poseidon() {
        const WIDTH: usize = 3;
        const RATE: usize = 2;

        let m1 = Fp::from(1);
        let m2 = Fp::from(2);


        let hash_result = poseidon::Hash::<_, MySpec<WIDTH, RATE>, ConstantLength<RATE>, WIDTH, RATE>::init()
            .hash([m1, m2]);
        println!("m1 {m1:?} m2 {m2:?} hash_result {hash_result:?}");
    }
}