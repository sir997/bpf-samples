mod bpf;
use std::time::Duration;

use crate::bpf::*;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};

fn main() {
    let mut skel = MinimalSkelBuilder::default().open().unwrap();
    skel.bss().mpid = std::process::id() as i32;
    let mut skel = skel.load().unwrap();
    skel.attach().unwrap();
    println!("attach success");
    
    loop {
        std::thread::sleep(Duration::from_secs(1));
        eprint!(".");
    }
}
