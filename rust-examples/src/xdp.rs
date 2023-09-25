mod bpf;

use std::{thread, time::Duration};

use bpf::*;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};

fn main() {
    let builder = XdpSkelBuilder::default();
    let skel = builder.open().unwrap();
    let mut skel = skel.load().unwrap();
    skel.attach().unwrap();

    print!("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.\n");


    loop {
        eprint!(".");
        thread::sleep(Duration::from_secs(1));
    }
}
