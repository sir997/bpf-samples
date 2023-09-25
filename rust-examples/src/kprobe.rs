mod bpf;

use std::time::Duration;

use libbpf_rs::skel::SkelBuilder;

use crate::bpf::*;
use libbpf_rs::skel::OpenSkel;

fn main() {
    let builder = KprobeSkelBuilder::default();
    let skel = builder.open().unwrap();
    let _ = skel.load().unwrap();

    print!("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.\n");

    loop {
        std::thread::sleep(Duration::from_secs(1));
        eprint!(".");
    }
}
