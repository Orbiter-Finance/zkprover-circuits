/*
For the deposit ticket, withdraw ticket, gas Cost ticket
 */

use std::marker::PhantomData;

use ethers::abi::encode_packed;
use ethers::abi::Token;
use ethers::core::utils::keccak256;
use ethers::types::{Address, U256};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    halo2curves::bn256::Fq,
    halo2curves::FieldExt,
    plonk::{Column, Error, Instance, Selector},
};

#[derive(Clone)]
pub struct HashData<F: FieldExt>(AssignedCell<F, F>);

#[derive(Debug, Clone)]
pub(crate) struct GasTicketConfig<
    F: FieldExt,
    const DEPOSIT_TICKET_NUM: usize,
    const WITHDRAW_TICKET_NUM: usize,
    const LAST_BATCH_TX_NUM: usize,
> {
    pub deposit_ticket: Column<Instance>,
    pub withdraw_ticket: Column<Instance>,
    pub last_batch_tx_gas_hash: Column<Instance>,
    pub s: Selector,
    pub _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub(crate) struct GasTicketData {
    pub(crate) address: Address,
    pub(crate) block_timestamp: U256,
    pub(crate) deposit_balance: U256,
}

impl GasTicketData {
    pub fn encode(&self) -> Vec<u8> {
        let tokens = [
            Token::Address(self.address),
            Token::Uint(self.block_timestamp),
            Token::Uint(self.deposit_balance),
        ];
        encode_packed(&tokens).unwrap()
    }

    pub fn hash(&self) -> [u8; 32] {
        keccak256(self.encode())
    }

    pub fn bn256_fq_hash(&self) -> Fq {
        Fq::from_bytes(&self.hash()).unwrap()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct TxGasTicketData {
    pub(crate) tx_hash: U256, // Bytes32 To U256
    pub(crate) gas: U256,
}

#[derive(Clone, Debug)]
pub(crate) struct PreBatchTxGas {
    pub(crate) tx_gas_ticket_data: Vec<TxGasTicketData>,
}

impl PreBatchTxGas {
    pub fn encode(&self) -> Vec<u8> {
        let mut tokens: Vec<Token> = [].to_vec();
        for gas_ticket in &self.tx_gas_ticket_data {
            let mut it = vec![Token::Uint(gas_ticket.tx_hash), Token::Uint(gas_ticket.gas)];
            tokens.append(&mut it)
        }
        encode_packed(&tokens).unwrap()
    }

    pub fn hash(&self) -> [u8; 32] {
        keccak256(self.encode())
    }

    pub fn bn256_fq_hash(&self) -> Fq {
        Fq::from_bytes(&self.hash()).unwrap()
    }
}

#[derive(Debug)]
pub(crate) struct GasTicketChip<F: FieldExt, const TX_NUM: usize> {
    pub _marker: PhantomData<F>,
    pub deposit_ticket_data: Vec<GasTicketData>,
    pub withdraw_ticket_data: Vec<GasTicketData>,
    pub pre_batch_tx_gas_data: PreBatchTxGas,
}

impl<F: FieldExt, const TX_NUM: usize> GasTicketChip<F, TX_NUM> {
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        config: &GasTicketConfig<F, 32, 32, 32>,
        deposit_hash_datas: Vec<HashData<F>>,
        withdraw_hash_datas: Vec<HashData<F>>,
        last_batch_tx_gas_hash: HashData<F>,
    ) -> Result<(), Error> {
        layouter.constrain_instance(
            last_batch_tx_gas_hash.0.cell(),
            config.last_batch_tx_gas_hash,
            0,
        );

        for i in 0..deposit_hash_datas.len() {
            layouter.constrain_instance(deposit_hash_datas[i].0.cell(), config.deposit_ticket, i);
        }
        for i in 0..withdraw_hash_datas.len() {
            layouter.constrain_instance(withdraw_hash_datas[i].0.cell(), config.withdraw_ticket, i);
        }
        Ok(())
    }

    // pub fn constraint_gas_data(
    //     &self,
    //     layouter: &mut impl Layouter<F>,
    //     config: &GasTicketConfig<F, 32, 32, 32>,
    // ) -> Result<(Vec<HashData<F>>, Vec<HashData<F>>, HashData<F>), Error> {
    //     let deposit_ticket_hash: Vec<F> =
    //         self.deposit_ticket_data.iter().map(|data|
    // data.bn256_fp_hash()).collect(); }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_hash() {}
}
