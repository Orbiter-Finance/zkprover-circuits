use halo2_proofs::halo2curves::{FieldExt, bn256::Fr};

use halo2_gadgets::poseidon::primitives::{
    Spec, Domain, Hash, P128Pow5T3
};
use hash_circuit::poseidon::primitives::ConstantLengthIden3;

/// indicate an field can be hashed in merkle tree (2 Fields to 1 Field)
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

//     type SpecType = P128Pow5T3<Self>;
//     type DomainType = ConstantLengthIden3<2>;

//     fn hash(inp: [Self; 2]) -> Self {
//         Self::hasher().hash(inp)
//     }
// }

#[cfg(test)]
mod tests {

    use halo2_gadgets::poseidon::{
        primitives::{self as poseidon, P128Pow5T3, ConstantLength}
    };
    use halo2_proofs::halo2curves::pasta::Fp;
    // pub use halo2_proofs::halo2curves::bn256::Fr as Fp;
    // use crate::{test_utils::{Fp},};
    #[test]
    fn test_poseidon() {
        let message = [Fp::from(1), Fp::from(2)];
        let output = poseidon::Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash(message);
    }
}
