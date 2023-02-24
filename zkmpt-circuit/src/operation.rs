use super::serde;
use halo2_proofs::arithmetic::FieldExt;
use hash_circuit::Hashable;

/// Represent an account operation in MPT
#[derive(Clone, Debug, Default)]
pub struct AccountOp<Fp: FieldExt> {
    /// the state before updating in account
    pub account_before: Option<Account<Fp>>,
    /// the state after updating in account
    pub account_after: Option<Account<Fp>>,
}

/// include error raised in deserialize or data verification
#[derive(Debug)]
pub enum TraceError {
    /// error in deserialize
    DeErr(std::io::Error),
    /// error for malform data
    DataErr(String),
}

fn bytes_to_fp<Fp: FieldExt>(mut bt: Vec<u8>) -> std::io::Result<Fp> {
    // let expected_size = Fp::NUM_BITS as usize / 8 + if Fp::NUM_BITS % 8 == 0 { 0
    // } else { 1 };
    bt.resize(64, 0u8);
    let arr: [u8; 64] = bt
        .as_slice()
        .try_into()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    Ok(Fp::from_bytes_wide(&arr))
}

// impl<'d, Fp: Hashable> TryFrom<&'d serde::AccountStateData> for Account<Fp> {
//     type Error = TraceError;

//     fn try_from(acc_trace: &'d serde::AccountStateData) -> Result<Self,
// Self::Error> {         let nonce = Fp::from(acc_trace.nonce);
//         let gas_balance =
// bytes_to_fp(acc_trace.gas_balance.to_bytes_le()).map_err(TraceError::DeErr)?;
//         let
//     }
// }

// impl<'d, Fp: Hashable> TryFrom<&'d serde::MPTTransTrace> for AccountOp<Fp> {
//     type Error = TraceError;

//     fn try_from(trace: &'d serde::MPTTransTrace) -> Result<Self, Self::Error>
// {

//         let account_before = {
//             trace.account_update.unwrap().old_account_state
//             let account: Account<Fp> =
//         };

//         Ok(Self {
//             account_before,
//             account_after,
//         })
//     }
// }

/// Represent for a zkProver account
#[derive(Clone, Debug, Default)]
pub struct Account<Fp> {
    /// the gasBalance of account
    pub gas_balance: Fp,
    /// the nonce of an account
    pub nonce: Fp,
    /// the 256-bit tx_hash require 2 field (first / last 128bit) to contain
    pub recrusive_tx_hash: Fp,
    pub tx_hash: Fp,
    pub pre_recrusive_tx_hash: Fp,

    /// the root of state trie
    pub state_root: Fp,
    /// cached traces
    pub hash_traces: Vec<(Fp, Fp, Fp)>,
}

/// impl
impl<Fp: FieldExt> Account<Fp> {
    /// calculating all traces ad-hoc with hasher function
    pub(crate) fn trace(mut self, mut hasher: impl FnMut(&Fp, &Fp) -> Fp) -> Self {
        self.recrusive_tx_hash = hasher(&self.pre_recrusive_tx_hash, &self.tx_hash);
        let h3 = hasher(&self.nonce, &self.gas_balance);
        let h2 = hasher(&self.recrusive_tx_hash, &self.state_root);
        let h_final = hasher(&h3, &h2);

        self.hash_traces = vec![
            (
                self.pre_recrusive_tx_hash,
                self.tx_hash,
                self.recrusive_tx_hash,
            ),
            (self.recrusive_tx_hash, self.state_root, h2),
            (self.nonce, self.gas_balance, h3),
            (h3, h2, h_final),
        ];

        self
    }
    /// complete
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

/// test
#[cfg(test)]
mod tests {

    use halo2_proofs::halo2curves::group::ff::PrimeField;
    use hash_circuit::{hash, poseidon::Hash, Hashable};
    use num_bigint::BigUint;
    use std::vec;

    use crate::test_utils::{hash_str_to_fp, Fp};

    use super::{bytes_to_fp, Account, TraceError};

    #[test]
    fn atonomy_bytes_data() {
        let gas_balance: Fp = bytes_to_fp(
            BigUint::from_bytes_be(
                b"0x1ffffffffffffffffffffffffffffffffffffffffffd5a5fa703d6131f2c2e5",
            )
            .to_bytes_le(),
        )
        .unwrap();
        println!("gasbalance {gas_balance:?}")
    }

    /// test
    #[test]
    fn trace_account_data() {

        let tx_hash_vec = vec![
            hash_str_to_fp("0x26af0428e16c2e77b72b7ff2bfee86292f61c02dce0f25f8a8651a662245b818"),
            hash_str_to_fp("0x86073f5c72cad966e40b0bf3538a1c95e5cb93e34fa455951dfe760797a79016"),
            hash_str_to_fp("0x245f586b79e1efff0f3edf628b054cc4fa6cb62655d369f3675a6493ab9509a0"),
        ];
        let mut final_tx_hash: Fp = Fp::zero();
        for i in 0..tx_hash_vec.len() {
            final_tx_hash = Fp::hash([final_tx_hash, tx_hash_vec[i]]);
        }

        let account: Account<Fp> = Account {
            nonce: Fp::from(1u64),
            gas_balance: Fp::from(1000u64),
            tx_hash: hash_str_to_fp(
                "0xfb8fc76b0dd70729afc7eb236fbcb772770e306acb145552c19c045f0211b75e",
            ),
            recrusive_tx_hash: hash_str_to_fp(
                "0xd84ef25cb42fd625f0b37e2051b1265e7cb7d8f2c4e267222220cfa8d1a439a9",
            ),
            state_root: hash_str_to_fp(
                "0x7739c67431d2c13dbcfb87502eafa7c21d17680a64b699b250d42b6f09e9e6ba",
            ),
            ..Default::default()
        };

        let data = account.complete(|a, b| <Fp as Hashable>::hash([*a, *b]));
        println!("data hash {:?}", data.account_hash());

        assert_eq!(
            data.account_hash(),
            hash_str_to_fp("0x0003c9a939086ff447da8b4b33b4ba6b10fb9044b17755feb49932d10c30aa67")
        );
    }
}
