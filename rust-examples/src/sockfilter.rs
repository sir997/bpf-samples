mod bpf;

use std::{
    io,
    net::Ipv4Addr,
    os::fd::{AsFd, AsRawFd, RawFd},
    time::Duration,
};

use bpf::*;
use libbpf_rs::{
    libbpf_sys::__be32,
    skel::{OpenSkel, SkelBuilder},
    RingBufferBuilder,
};
use libc::{AF_PACKET, ETH_P_ALL};

#[repr(C)]
struct SoEvent {
    src_addr: __be32,
    dst_addr: __be32,
    ports: __be32,
    ip_proto: u32,
    pkt_type: u32,
    ifindex: u32,
}

fn handle_event(data: &[u8]) -> i32 {
    if data.len() != std::mem::size_of::<SoEvent>() {
        eprintln!(
            "Invalid size {} != {}",
            data.len(),
            std::mem::size_of::<SoEvent>()
        );
    }

    let event = unsafe { &*(data.as_ptr() as *const SoEvent) };

    let src_addr = Ipv4Addr::from(event.src_addr.to_be());
    let dst_addr = Ipv4Addr::from(event.dst_addr.to_be());

    let src_port = event.ports >> 16;
    let dst_port = event.ports & 0xF;

    println!(
        "interface: {}\tprotocol: {}\t{}:{}(src) -> {}:{}(dst)\n",
        "", event.ip_proto, src_addr, src_port, dst_addr, dst_port,
    );

    0
}

fn open_raw_sock() -> io::Result<RawFd> {
    unsafe {
        let sock = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        );
        if sock < 0 {
            println!("failed to create new socket");
            return Err(io::Error::last_os_error());
        }

        let mut sll: libc::sockaddr_ll = std::mem::zeroed();
        sll.sll_family = AF_PACKET as u16;
        sll.sll_ifindex = 1;
        sll.sll_protocol = (ETH_P_ALL as u16).to_be();

        let ret = libc::bind(
            sock,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        );
        if ret < 0 {
            libc::close(sock);
            return Err(io::Error::last_os_error());
        }

        Ok(sock)
    }
}

fn main() -> anyhow::Result<()> {
    let builder = SockfilterSkelBuilder::default();
    let skel = builder.open()?;
    let skel = skel.load()?;

    println!("attach success");

    let maps = skel.maps();
    let mut builder = RingBufferBuilder::new();
    builder.add(&maps.rb(), handle_event)?;
    let rb = builder.build()?;

    let sock = open_raw_sock()?;
    println!("open raw sock: {}", sock);

    let prog_fd = skel.progs().socket_handler().as_fd().as_raw_fd();
    println!("prog_fd: {}", prog_fd);

    let value = &prog_fd as *const i32 as *const libc::c_void;
    unsafe {
        let ret = libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_BPF,
            value,
            std::mem::size_of_val(&prog_fd) as u32,
        );
        println!("setsockopt ret: {}", ret);
        if ret < 0 {
            anyhow::bail!("setsockopt ret: {}", ret);
        }
    }

    while rb.poll(Duration::from_millis(100)).is_ok() {}

    Ok(())
}
