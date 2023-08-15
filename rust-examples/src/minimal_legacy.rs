mod bpf;
use std::time::Duration;

use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    MapFlags,
};

use crate::bpf::*;

fn main() {
    let skel = MinimalLegacySkelBuilder::default().open().unwrap();
    let mut skel = skel.load().unwrap();
    let index = 0u32.to_ne_bytes();
    let pid = std::process::id().to_ne_bytes();
    skel.maps()
        .my_pid_map()
        .update(&index, &pid, MapFlags::ANY)
        .unwrap();

    skel.attach().unwrap();

    println!("attach success! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe`");

    loop {
        std::thread::sleep(Duration::from_secs(1));
        eprint!(".");
    }
}
