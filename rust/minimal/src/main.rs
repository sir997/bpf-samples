mod bpf;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;

use std::io::Write;
use std::time::Duration;

fn main() {
    let builder = bpf::MinimalSkelBuilder::default();
    let mut skel = builder.open().unwrap();

    skel.bss().my_pid = std::process::id() as i32;

    let mut skel = skel.load().unwrap();

    skel.attach().unwrap();

    println!("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` ");

    loop {
        std::thread::sleep(Duration::from_secs(1));
        print!(".");
        std::io::stdout().flush().unwrap();
    }
}
