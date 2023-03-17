use std::fs::File;
use std::io::Read;
use halo2_proofs::dev::MockProver;
pub use halo2_proofs::halo2curves::bn256::Fr as Fp;
use hash_circuit::Hashable;
use zkprover_mpt_circuits::{serde::{BlockResult, MPTTransTrace}, operation::AccountOp};
use zkprover_mpt_circuits::{state_trie::StateTrie};
use serde::Deserialize;


fn main() {
    let mut buffer = Vec::new();
    let mut f = File::open("zkmpt-circuit/integration-test/trace.json").unwrap();
    f.read_to_end(&mut buffer).unwrap();
    // println!("buffer {buffer:?}");

    let block_result = serde_json::from_slice::<BlockResult>(&buffer).unwrap();
    let traces = block_result.mpt_trans_trace;
    let start_mpt_root = block_result.start_mpt_root;
    let end_mpt_root = block_result.end_mpt_root;

    let ops: Vec<AccountOp<Fp>> = traces.iter().map(|tr| tr.try_into().unwrap()).collect();
    println!("ops {ops:?}");

    let mut state_trie: StateTrie<Fp> = Default::default();
    state_trie.add_ops(ops);

    let final_root = state_trie.final_root();
    println!("final_root {final_root:?}");
    println!("mpt_trans_trace {traces:?}");

    let state_circuit = state_trie.circuits(7, &[]);

    // let prover_state = MockProver::<Fp>::run(7, &state_circuit, vec![]);

   
}
