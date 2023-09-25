mod bpf;

use std::time::Duration;

use bpf::*;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};

fn main() {
    let builder = FentrySkelBuilder::default();
    let skel = builder.open().unwrap();
    let mut skel = skel.load().unwrap();

    skel.attach().unwrap();

    print!("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.\n");

    loop {
        std::thread::sleep(Duration::from_secs(1));
        eprint!(".");
    }
}
