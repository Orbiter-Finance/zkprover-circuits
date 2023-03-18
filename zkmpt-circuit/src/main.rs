use std::env;
use std::time::Duration;
use tokio::{task, time};

pub async fn pull_bundler_mission() {
    println!("do sth");
}

/// cargo run  -- /tmp/smt-store-dir
#[tokio::main]
pub async fn main() {
    let args: Vec<String> = env::args().collect();
    let db_path = args.get(1).expect("args db_path not found");
    println!("db_path {:?}", db_path);
    // futures::future::pending().await

    let forever = task::spawn(async {
        let mut interval = time::interval(Duration::from_millis(1000));

        loop {
            interval.tick().await;
            pull_bundler_mission().await;
        }
    });

    forever.await;
}
