use std::{fs::File, io::Read, marker::PhantomData};

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::pairing::MultiMillerLoop,
    plonk::{Circuit, ConstraintSystem, Error},
};
use itertools::Itertools;

use jsonrpsee::tracing::log::error;
use std::fmt::Debug;

use lazy_static::lazy_static;

lazy_static! {
    pub static ref MOCK_RPC_TXS: BundlerRpcData = {
        let mut buffer = Vec::new();
        let mut f = File::open("src/ERC4337/rpc_data_test.json").unwrap();
        f.read_to_end(&mut buffer).unwrap();
        serde_json::from_slice::<BundlerRpcData>(&buffer).unwrap()
    };
}

use crate::{
    gadgets::hashes_sum::{SumChip, SumConfig},
    ERC4337::bundler::BundlerRpcData,
};

/// Represents a point in bytes.
#[derive(Copy, Clone)]
pub struct Serialized([u8; 64]);

impl Default for Serialized {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl AsMut<[u8]> for Serialized {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

use crate::{
    gadgets::sign_verify::SignData, serde::Hash, verifier::circuit_deploy::TargetCircuit,
    ERC4337::bundler::Transaction,
};

// entry point
#[derive(Clone, Debug)]
pub struct ZkProverCircuitConfig<Fp: FieldExt> {
    sum_config: SumConfig<Fp>,
    _marker: PhantomData<Fp>,
}

impl<Fp: FieldExt> ZkProverCircuitConfig<Fp> {
    pub fn new(meta: &mut ConstraintSystem<Fp>) -> Self {
        let sum_config = SumChip::configure(meta);
        ZkProverCircuitConfig {
            sum_config,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ZkProverCircuit<Fp: FieldExt, const TX_NUM: usize> {
    // the maxium records in circuits (would affect vk)
    pub mpt_root_before: Fp,
    pub mpt_root_after: Fp,
    //  pub mpt_proofs: Vec<>
    pub txs: Vec<Transaction>,
    //  pub ops: Vec<AccountOp<Fp>>,
    pub chain_id: u64,

    pub hash_sum_chip: SumChip<Fp>,
    // pub tx_verify_chip:

    // for the test mock data
    pub mock_hashes_element: Vec<Value<Fp>>,
    pub mock_hashes_sum: Value<Fp>,
    pub mock_zero: Value<Fp>,
}

impl<Fp: FieldExt, const TX_NUM: usize> Default for ZkProverCircuit<Fp, TX_NUM> {
    fn default() -> Self {
        let mut buffer = Vec::new();
        let mut f = File::open("src/ERC4337/rpc_data_test.json").unwrap();
        f.read_to_end(&mut buffer).unwrap();
        // println!("buffer {buffer:?}");

        let rpc_txs = serde_json::from_slice::<BundlerRpcData>(&buffer)
            .unwrap()
            .result
            .unwrap()
            .tx_list;

        const TX_NUM: usize = 2;
        let k = 7;

        let mock_element_list = vec![
            Value::known(Fp::from(1)),
            Value::known(Fp::from(2)),
            Value::known(Fp::from(3)),
            Value::known(Fp::from(4)),
            Value::known(Fp::from(5)),
        ];
        let mock_zero = Value::known(Fp::from(0));
        let mock_hashes_sum = Value::known(Fp::from(15));

        Self {
            mpt_root_before: Fp::from(0),
            mpt_root_after: Fp::from(0),
            txs: rpc_txs.iter().map(|tr| tr.try_into().unwrap()).collect(),
            chain_id: 5u64,
            hash_sum_chip: SumChip {
                _marker: PhantomData::default(),
            },
            mock_hashes_element: mock_element_list,
            mock_hashes_sum,
            mock_zero,
        }
    }
}

impl<Fp: FieldExt, const TX_NUM: usize> ZkProverCircuit<Fp, TX_NUM> {
    // Constructs a new ZkProverCircuit

    pub fn random() -> Self {
        // let mut buffer = Vec::new();
        // let mut f = File::open("zkmpt-circuit/src/ERC4337/rpc_data_test.json").unwrap();
        // f.read_to_end(&mut buffer).unwrap();

        let mut parsed_data = r#"
        {
            "jsonrpc": "2.0",
            "result": {
              "batchHash": "0x567e81b35c977af2c177251847b61e95f71b6bbf272c27208dc095590807577d",
              "txList": [
                {
                  "hash": "0x781621f07006028e52e322fcab95c31dec73fa5cda479b2f72d09f66ed83811d",
                  "nonce": "0x74",
                  "blockHash": null,
                  "blockNumber": null,
                  "transactionIndex": null,
                  "from": "0x6ce4D9694c1626862234216bA78874dE70903A71",
                  "to": null,
                  "value": "0x00",
                  "gasPrice": "0x1b3797888e",
                  "gas": "0x0ae65d",
                  "input": "0x60806040523480156200001157600080fd5b506040518060400160405280600e81526020016d2d25a83937bb32b9102a37b5b2b760911b815250604051806040016040528060038152602001622d282160e91b81525081600390816200006691906200020b565b5060046200007582826200020b565b50505062000096336b204fce5e3e250261100000006200009c60201b60201c565b620002ff565b6001600160a01b038216620000f75760405162461bcd60e51b815260206004820152601f60248201527f45524332303a206d696e7420746f20746865207a65726f206164647265737300604482015260640160405180910390fd5b80600260008282546200010b9190620002d7565b90915550506001600160a01b038216600081815260208181526040808320805486019055518481527fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef910160405180910390a35050565b505050565b634e487b7160e01b600052604160045260246000fd5b600181811c908216806200019257607f821691505b602082108103620001b357634e487b7160e01b600052602260045260246000fd5b50919050565b601f8211156200016257600081815260208120601f850160051c81016020861015620001e25750805b601f850160051c820191505b818110156200020357828155600101620001ee565b505050505050565b81516001600160401b0381111562000227576200022762000167565b6200023f816200023884546200017d565b84620001b9565b602080601f8311600181146200027757600084156200025e5750858301515b600019600386901b1c1916600185901b17855562000203565b600085815260208120601f198616915b82811015620002a85788860151825594840194600190910190840162000287565b5085821015620002c75787850151600019600388901b60f8161c191681555b5050505050600190811b01905550565b80820180821115620002f957634e487b7160e01b600052601160045260246000fd5b92915050565b610a1d806200030f6000396000f3fe608060405234801561001057600080fd5b50600436106100d45760003560e01c806340c10f1911610081578063a457c2d71161005b578063a457c2d7146101a7578063a9059cbb146101ba578063dd62ed3e146101cd57600080fd5b806340c10f191461016157806370a082311461017657806395d89b411461019f57600080fd5b806323b872dd116100b257806323b872dd1461012c578063313ce5671461013f578063395093511461014e57600080fd5b806306fdde03146100d9578063095ea7b3146100f757806318160ddd1461011a575b600080fd5b6100e1610206565b6040516100ee9190610890565b60405180910390f35b61010a6101053660046108fa565b610298565b60405190151581526020016100ee565b6002545b6040519081526020016100ee565b61010a61013a366004610924565b6102b2565b604051601281526020016100ee565b61010a61015c3660046108fa565b6102d6565b61017461016f3660046108fa565b610315565b005b61011e610184366004610960565b6001600160a01b031660009081526020819052604090205490565b6100e1610381565b61010a6101b53660046108fa565b610390565b61010a6101c83660046108fa565b61043a565b61011e6101db366004610982565b6001600160a01b03918216600090815260016020908152604080832093909416825291909152205490565b606060038054610215906109b5565b80601f0160208091040260200160405190810160405280929190818152602001828054610241906109b5565b801561028e5780601f106102635761010080835404028352916020019161028e565b820191906000526020600020905b81548152906001019060200180831161027157829003601f168201915b5050505050905090565b6000336102a6818585610448565b60019150505b92915050565b6000336102c085828561056c565b6102cb8585856105fe565b506001949350505050565b3360008181526001602090815260408083206001600160a01b03871684529091528120549091906102a690829086906103109087906109ef565b610448565b68056bc75e2d631000008111156103735760405162461bcd60e51b815260206004820152600f60248201527f416d6f756e74206f766572666c6f77000000000000000000000000000000000060448201526064015b60405180910390fd5b61037d82826107d1565b5050565b606060048054610215906109b5565b3360008181526001602090815260408083206001600160a01b03871684529091528120549091908381101561042d5760405162461bcd60e51b815260206004820152602560248201527f45524332303a2064656372656173656420616c6c6f77616e63652062656c6f7760448201527f207a65726f000000000000000000000000000000000000000000000000000000606482015260840161036a565b6102cb8286868403610448565b6000336102a68185856105fe565b6001600160a01b0383166104aa5760405162461bcd60e51b8152602060048201526024808201527f45524332303a20617070726f76652066726f6d20746865207a65726f206164646044820152637265737360e01b606482015260840161036a565b6001600160a01b03821661050b5760405162461bcd60e51b815260206004820152602260248201527f45524332303a20617070726f766520746f20746865207a65726f206164647265604482015261737360f01b606482015260840161036a565b6001600160a01b0383811660008181526001602090815260408083209487168084529482529182902085905590518481527f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925910160405180910390a3505050565b6001600160a01b0383811660009081526001602090815260408083209386168352929052205460001981146105f857818110156105eb5760405162461bcd60e51b815260206004820152601d60248201527f45524332303a20696e73756666696369656e7420616c6c6f77616e6365000000604482015260640161036a565b6105f88484848403610448565b50505050565b6001600160a01b03831661067a5760405162461bcd60e51b815260206004820152602560248201527f45524332303a207472616e736665722066726f6d20746865207a65726f20616460448201527f6472657373000000000000000000000000000000000000000000000000000000606482015260840161036a565b6001600160a01b0382166106dc5760405162461bcd60e51b815260206004820152602360248201527f45524332303a207472616e7366657220746f20746865207a65726f206164647260448201526265737360e81b606482015260840161036a565b6001600160a01b0383166000908152602081905260409020548181101561076b5760405162461bcd60e51b815260206004820152602660248201527f45524332303a207472616e7366657220616d6f756e742065786365656473206260448201527f616c616e63650000000000000000000000000000000000000000000000000000606482015260840161036a565b6001600160a01b03848116600081815260208181526040808320878703905593871680835291849020805487019055925185815290927fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef910160405180910390a36105f8565b6001600160a01b0382166108275760405162461bcd60e51b815260206004820152601f60248201527f45524332303a206d696e7420746f20746865207a65726f206164647265737300604482015260640161036a565b806002600082825461083991906109ef565b90915550506001600160a01b038216600081815260208181526040808320805486019055518481527fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef910160405180910390a35050565b600060208083528351808285015260005b818110156108bd578581018301518582016040015282016108a1565b506000604082860101526040601f19601f8301168501019250505092915050565b80356001600160a01b03811681146108f557600080fd5b919050565b6000806040838503121561090d57600080fd5b610916836108de565b946020939093013593505050565b60008060006060848603121561093957600080fd5b610942846108de565b9250610950602085016108de565b9150604084013590509250925092565b60006020828403121561097257600080fd5b61097b826108de565b9392505050565b6000806040838503121561099557600080fd5b61099e836108de565b91506109ac602084016108de565b90509250929050565b600181811c908216806109c957607f821691505b6020821081036109e957634e487b7160e01b600052602260045260246000fd5b50919050565b808201808211156102ac57634e487b7160e01b600052601160045260246000fdfea164736f6c6343000811000a",
                  "v": "0x2D",
                  "r": "0x5fbe4bc25096bed5adbf6470de6dee5788adbc5c2d563cacf5997f74323cfa03",
                  "s": "0x1a04acd7c50cb5866efd1ce6dfb5a6e1b59787e0ebd55ce22bad78ea809d4441",
                  "type": "0x0",
                  "accessList": [],
                  "maxPriorityFeePerGas": null,
                  "maxFeePerGas": null,
                  "chainId": "0x5"
                }
              ],
              "status": 1
            },
            "id": 1
          }
          
        "#.as_bytes();
        // println!("buffer {buffer:?}");

        let rpc_txs = serde_json::from_slice::<BundlerRpcData>(&parsed_data)
            .unwrap()
            .result
            .unwrap()
            .tx_list;

        const TX_NUM: usize = 2;
        let k = 7;

        let mock_element_list = vec![
            Value::known(Fp::from(1)),
            Value::known(Fp::from(2)),
            Value::known(Fp::from(3)),
            Value::known(Fp::from(4)),
            Value::known(Fp::from(5)),
        ];
        let mock_zero = Value::known(Fp::from(0));
        let mock_hashes_sum = Value::known(Fp::from(15));

        Self {
            mpt_root_before: Fp::from(0),
            mpt_root_after: Fp::from(0),
            txs: rpc_txs.iter().map(|tr| tr.try_into().unwrap()).collect(),
            chain_id: 5u64,
            hash_sum_chip: SumChip {
                _marker: PhantomData::default(),
            },
            mock_hashes_element: mock_element_list,
            mock_hashes_sum,
            mock_zero,
        }
    }
}

impl<Fp: FieldExt, const TX_NUM: usize> Circuit<Fp> for ZkProverCircuit<Fp, TX_NUM> {
    type Config = ZkProverCircuitConfig<Fp>;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        // ZkProverCircuitConfig::configure(meta)

        ZkProverCircuitConfig::new(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let sign_datas: Vec<SignData> = self
            .txs
            .iter()
            .map(|tx| {
                tx.sign_data().map_err(|e| {
                    error!("tx_to_sign_data error for tx {:?}", tx);
                    e
                })
            })
            .try_collect()
            .unwrap();

        let hash_sum = self
            .hash_sum_chip
            .constraint_list_sum(
                &mut layouter,
                &config.sum_config,
                &self.mock_hashes_element,
                self.mock_zero,
            )
            .unwrap();

        // start expose public inputs

        // for the Tx hashes Sum
        self.hash_sum_chip
            .expose_public(layouter, &config.sum_config, hash_sum, 0)
            .unwrap();

        // end expose public inputs

        Ok(())
    }
}

pub struct IntergrateCircuit;

impl<E: MultiMillerLoop> TargetCircuit<E> for IntergrateCircuit {
    const TARGET_CIRCUIT_K: u32 = 10;
    const PUBLIC_INPUT_SIZE: usize = 1;
    const N_PROOFS: usize = 2;
    const NAME: &'static str = "zkProver_circuit";
    const PARAMS_NAME: &'static str = "zkProver_circuit";
    const READABLE_VKEY: bool = true;

    type Circuit = ZkProverCircuit<E::Scalar, 128>;

    fn instance_builder() -> (Self::Circuit, Vec<Vec<E::Scalar>>) {
        let circuit = ZkProverCircuit {
            mpt_root_before: todo!(),
            mpt_root_after: todo!(),
            txs: todo!(),
            chain_id: todo!(),
            hash_sum_chip: todo!(),
            mock_hashes_element: todo!(),
            mock_hashes_sum: todo!(),
            mock_zero: todo!(),
        };
        let instances = vec![];
        (circuit, instances)
    }

    fn load_instances(buf: &[u8]) -> Vec<Vec<Vec<E::Scalar>>> {
        vec![vec![]]
    }
}

#[cfg(test)]
mod tests {

    use std::{fs::File, io::Read, marker::PhantomData, path::Path};

    use crate::{
        gadgets::hashes_sum::SumChip,
        test_utils::Fp,
        verifier::{evm_verify, gen_evm_verifier},
        zkprover_circuit::MOCK_RPC_TXS,
    };
    use halo2_proofs::{
        circuit::Value,
        dev::MockProver,
        halo2curves::{bn256::Bn256, pairing::Engine},
        plonk::keygen_pk,
    };

    use crate::{
        verifier::{
            circuit_deploy::{
                keygen, load_target_circuit_params, load_target_circuit_vk, sample_circuit_setup,
                TargetCircuit,
            },
            gen_proof,
        },
        ERC4337::bundler::BundlerRpcData,
    };

    use super::{IntergrateCircuit, ZkProverCircuit};
    #[test]
    fn test_zkprover_circuit() {
        let mut buffer = Vec::new();
        let mut f = File::open("src/ERC4337/rpc_data_test.json").unwrap();
        f.read_to_end(&mut buffer).unwrap();
        // println!("buffer {buffer:?}");

        let rpc_txs = MOCK_RPC_TXS.clone().result.unwrap().tx_list;

        const TX_NUM: usize = 2;
        let k = 7;

        let mock_element_list = vec![
            Value::known(Fp::from(1)),
            Value::known(Fp::from(2)),
            Value::known(Fp::from(3)),
            Value::known(Fp::from(4)),
            Value::known(Fp::from(5)),
        ];
        let mock_zero = Value::known(Fp::from(0));
        let mock_hashes_sum = Value::known(Fp::from(15));

        let circuit = ZkProverCircuit::<Fp, TX_NUM> {
            mpt_root_before: Fp::from(0),
            mpt_root_after: Fp::from(0),
            txs: rpc_txs.iter().map(|tr| tr.try_into().unwrap()).collect(),
            chain_id: 5u64,
            hash_sum_chip: SumChip {
                _marker: PhantomData::default(),
            },
            mock_hashes_element: mock_element_list,
            mock_hashes_sum,
            mock_zero,
        };

        let prover = MockProver::<Fp>::run(k, &circuit, vec![vec![Fp::from(15)]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        let mut folder = Path::new("output/").to_path_buf();
        let params = load_target_circuit_params::<Bn256, IntergrateCircuit>(&mut folder);
        let vk = load_target_circuit_vk::<Bn256, IntergrateCircuit>(&mut folder, &params);
        let pk = keygen(&params, circuit.clone()).unwrap();
        let deployment_code = gen_evm_verifier(&params, pk.get_vk(), vec![1]);
        let proof_bytes = gen_proof(&params, &pk, circuit, vec![vec![Fp::from(15)]]);
        evm_verify(deployment_code, vec![vec![Fp::from(15)]], proof_bytes);

        // println!("proof_bytes {:?}", hex::encode(proof_bytes));
    }

    #[test]
    fn test_circuit_setup_data() {
        sample_circuit_setup::<Bn256, IntergrateCircuit>("output/".into());
    }

    #[test]
    fn test_gen_proof() {}
}
