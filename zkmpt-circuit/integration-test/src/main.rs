use std::fs::File;
use std::io::Read;
use zkprover_mpt_circuits::serde::{BlockResult, MPTTransTrace};

use serde::Deserialize;

fn main() {
    let mut buffer = Vec::new();
    let mut f = File::open("zkmpt-circuit/integration-test/trace.json").unwrap();
    f.read_to_end(&mut buffer).unwrap();
    // println!("buffer {buffer:?}");

    let traces: Vec<MPTTransTrace> = serde_json::from_slice::<BlockResult>(&buffer)
        .unwrap()
        .mpt_trans_trace;

    println!("mpt_trans_trace {traces:?}");
        
}
