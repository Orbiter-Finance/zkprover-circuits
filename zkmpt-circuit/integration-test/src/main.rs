use std::fs::File;
use std::io::Read;
use zkprover_mpt_circuits::serde::{BlockResult, MPTTransTrace};

use serde::Deserialize;

fn gen_world_state() {
    
}

fn main() {
    let mut buffer = Vec::new();
    let mut f = File::open("zkmpt-circuit/integration-test/trace.json").unwrap();
    f.read_to_end(&mut buffer).unwrap();
    // println!("buffer {buffer:?}");

    let blockResult = serde_json::from_slice::<BlockResult>(&buffer).unwrap();
    let traces = blockResult.mpt_trans_trace;
    let startMptRoot = blockResult.start_mpt_root;
    let endMptRoot = blockResult.end_mpt_root;

    println!("mpt_trans_trace {traces:?}");
}
