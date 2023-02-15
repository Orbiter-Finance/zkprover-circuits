use crate::hash::Hashable;
use halo2_proofs::arithmetic::FieldExt;

/// Represent for a zkProver account
#[derive(Clone, Debug, Default)]
pub struct Account<Fp> {
    /// the gasBalance of account
    pub gas_balance: Fp,
    /// the nonce of an account
    pub nonce: Fp,
    /// the 256-bit tx_hash require 2 field (first / last 128bit) to contain
    pub tx_hash: (Fp, Fp),
    /// the root of state trie
    pub state_root: Fp,
    /// cached traces
    pub hash_traces: Vec<(Fp, Fp, Fp)>,
}

impl<Fp: FieldExt> Account<Fp> {
    /// calculating all traces ad-hoc with hasher function
    pub(crate) fn trace(mut self, mut hasher: impl FnMut(&Fp, &Fp) -> Fp) -> Self {
        let h1 = hasher(&self.tx_hash.0, &self.tx_hash.1);
        let h3 = hasher(&self.nonce, &self.gas_balance);
        let h2 = hasher(&h1, &self.state_root);
        let h_final = hasher(&h3, &h2);

        self.hash_traces = vec![
            (self.tx_hash.0, self.tx_hash.1, h1),
            (h1, self.state_root, h2),
            (self.nonce, self.gas_balance, h3),
            (h3, h2, h_final),
        ];

        self
    }

    // pub(crate) fn complete(self, hasher: impl FnMut(&Fp, &Fp) -> Fp) -> Self {
    //     if self.hash_traces.is_empty() {
    //         self.trace(hasher)
    //     } else {
    //         Self
    //     }
    // }

    pub(crate) fn complete(self, hasher: impl FnMut(&Fp, &Fp) -> Fp) -> Self {
        if self.hash_traces.is_empty() {
            self.trace(hasher)
        } else {
            self
        }
    }

    /// access the cached traces for calculated all hashes required in obtain
    /// the account hash there is totally 4 of them and the last one
    /// calculate the final hash
    pub fn hash_traces(&self, i: usize) -> Fp {
        if self.hash_traces.is_empty() {
            Fp::zero()
        } else {
            self.hash_traces[i].2
        }
    }

    /// the hash of account, which act as leaf value in account trie
    pub fn account_hash(&self) -> Fp {
        if self.hash_traces.is_empty() {
            Fp::zero()
        } else {
            assert_eq!(self.hash_traces.len(), 4);
            self.hash_traces[3].2
        }
    }
}

#[cfg(test)]
mod tests {

    use halo2_proofs::halo2curves::group::ff::PrimeField;
    use hash_circuit::Hashable;

    use crate::test_utils::{Fp};

    use super::Account;

    #[test]
    fn trace_account_data() {
        let account: Account<Fp> = Account {
            gas_balance: Fp::from(1000u64),
            nonce: Fp::from(1u64),
            tx_hash: (Fp::zero(), Fp::zero()),
            //0x20b24ebee7712fbbe84a15027eba4f1208e2e2df9f925de51b3382b86433e6a5
            state_root: Fp::from_str_vartime(
                "14789053415173694845992038966920525110567435779704439275440571405364058384037",
            )
            .unwrap(),
            ..Default::default()
        };

        let data = account.complete(|a, b| <Fp as Hashable>::hash([*a, *b]));
    }
}
