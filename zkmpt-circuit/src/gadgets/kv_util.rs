use halo2_proofs::halo2curves::FieldExt;
use hash_circuit::Hashable;

/// 2 fields for representing 32 byte, used for storage key or value, the hash
/// is also saved
#[derive(Clone, Debug, Default)]
pub struct KeyValue<Fp> {
    data: (Fp, Fp, Fp), // (the first 16 bytes, the second 16 bytes, hash value)
}

impl<Fp: FieldExt> KeyValue<Fp> {
    /// create object and omit the hash
    pub fn create_base(bytes32: (Fp, Fp)) -> Self {
        let (fst, snd) = bytes32;
        Self {
            data: (fst, snd, Fp::zero()),
        }
    }

    /// obtain the value pair
    pub fn val(&self) -> (Fp, Fp) {
        (self.data.0, self.data.1)
    }
    /// obtain the hash
    pub fn hash(&self) -> Fp {
        self.data.2
    }
    /// obtain the linear combination of two field
    pub fn lc(&self, randomness: Fp) -> Fp {
        self.data.0 + self.data.1 * randomness
    }
    /// obtain the linear combination of the value, in byte represent, which
    /// is common used in zkevm circuit
    /// the u256 is represented by le bytes and combined with randomness 1, o,
    /// o^2 ... o^31 on each and we calculate it from be represent
    pub fn u8_rlc(&self, randomness: Fp) -> Fp {
        let u128_hi = self.data.0.get_lower_128();
        let u128_lo = self.data.1.get_lower_128();
        u128_hi
            .to_be_bytes()
            .into_iter()
            .chain(u128_lo.to_be_bytes())
            .map(|bt| Fp::from(bt as u64))
            .reduce(|acc, f| acc * randomness + f)
            .expect("not empty")
    }
    /// obtain the first limb
    pub fn limb_0(&self) -> Fp {
        self.data.0
    }
    /// obtain the snd limb
    pub fn limb_1(&self) -> Fp {
        self.data.1
    }
}

impl<Fp: Hashable> KeyValue<Fp> {
    /// create object and also calc the hash
    pub fn create(bytes32: (Fp, Fp)) -> Self {
        let (fst, snd) = bytes32;
        let hash = <Fp as Hashable>::hash([fst, snd]);

        Self {
            data: (fst, snd, hash),
        }
    }

    /// return the triple group of hash
    pub fn hash_traces(&self) -> &(Fp, Fp, Fp) {
        &self.data
    }
}
