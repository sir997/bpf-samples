mod bpf;

use std::{mem, time::Duration};

use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    RingBufferBuilder,
};

use crate::bpf::*;

const TASK_COMM_LEN: usize = 16;
const MAX_FILENAME_LEN: usize = 127;

#[repr(C)]
struct Event {
    pid: i32,
    ppid: i32,
    exit_code: u32,
    duration_ns: u64,
    comm: [u8; TASK_COMM_LEN],
    filename: [u8; MAX_FILENAME_LEN],
    exit_event: bool,
}

fn main() {
    let skel = BootstrapSkelBuilder::default().open().unwrap();
    let mut skel = skel.load().unwrap();
    skel.attach().unwrap();

    let mut builder = RingBufferBuilder::new();
    let map = skel.maps();
    builder.add(map.rb(), handle_event).unwrap();
    let rb = builder.build().unwrap();

    println!(
        "{:<8} {:<5} {:<16} {:<7} {:<7} {}",
        "TIME", "EVENT", "COMM", "PID", "PPID", "FILENAME/EXIT CODE"
    );

    while rb.poll(Duration::from_millis(100)).is_ok() {}
}

fn handle_event(data: &[u8]) -> i32 {
    if data.len() != mem::size_of::<Event>() {
        eprintln!("Invalid size {} != {}", data.len(), mem::size_of::<Event>());
    }

    let now = chrono::Local::now().format("%H:%M:%S").to_string();

    let event = unsafe { &*(data.as_ptr() as *const Event) };
    let comm = String::from_utf8(event.comm.to_vec()).unwrap();
    if event.exit_event {
        let dur = std::time::Duration::from_nanos(event.duration_ns);
        println!(
            "{:<8} {:<5} {:<16} {:<7} {:<7} [{}] {:?}",
            now, "EXIT", comm, event.pid, event.ppid, event.exit_code, dur
        );
    } else {
        let filename = String::from_utf8(event.filename.to_vec()).unwrap();
        println!(
            "{:<8} {:<5} {:<16} {:<7} {:<7} {}",
            now, "EXEC", comm, event.pid, event.ppid, filename
        );
    }

    return 0;
}
