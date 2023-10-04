mod bpf;

use std::{
    io::{self},
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

    let src_addr = Ipv4Addr::from(u32::from_be(event.src_addr));
    let dst_addr = Ipv4Addr::from(u32::from_be(event.dst_addr));

    // 不确定这么写对不对
    // 凭感觉低16位是src，高16位是dst
    let src_port = u16::from_be((event.ports & 0xFF) as u16);
    let dst_port = u16::from_be((event.ports >> 16) as u16);

    let vec: Vec<u8>;
    unsafe {
        let mut ifarr: [libc::c_char; 16] = [0; 16];
        libc::if_indextoname(1, &mut ifarr[0]);
        vec = ifarr.iter().filter(|&&x| x > 0).map(|&x| x as u8).collect();
    }

    println!(
        "interface: {}\tprotocol: {}\t{}:{}(src) -> {}:{}(dst)\n",
        String::from_utf8(vec).unwrap(),
        ip_proto_mapping(event.ip_proto as i32),
        src_addr,
        src_port,
        dst_addr,
        dst_port,
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
        // cmd: ip a
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

fn ip_proto_mapping(proto: i32) -> String {
    match proto {
        libc::IPPROTO_IP => String::from("IP"),
        libc::IPPROTO_ICMP => String::from("ICMP"),
        libc::IPPROTO_IGMP => String::from("IGMP"),
        libc::IPPROTO_IPIP => String::from("IPIP"),
        libc::IPPROTO_TCP => String::from("TCP"),
        libc::IPPROTO_EGP => String::from("EGP"),
        libc::IPPROTO_PUP => String::from("PUP"),
        libc::IPPROTO_UDP => String::from("UDP"),
        libc::IPPROTO_IDP => String::from("IDP"),
        libc::IPPROTO_TP => String::from("TP"),
        libc::IPPROTO_DCCP => String::from("DCCP"),
        libc::IPPROTO_IPV6 => String::from("IPV6"),
        libc::IPPROTO_RSVP => String::from("RSVP"),
        libc::IPPROTO_GRE => String::from("GRE"),
        libc::IPPROTO_ESP => String::from("ESP"),
        libc::IPPROTO_AH => String::from("AH"),
        libc::IPPROTO_MTP => String::from("MTP"),
        libc::IPPROTO_BEETPH => String::from("BEETPH"),
        libc::IPPROTO_ENCAP => String::from("ENCAP"),
        libc::IPPROTO_PIM => String::from("PIM"),
        libc::IPPROTO_COMP => String::from("COMP"),
        libc::IPPROTO_SCTP => String::from("SCTP"),
        libc::IPPROTO_UDPLITE => String::from("UDPLITE"),
        libc::IPPROTO_MPLS => String::from("MPLS"),
        libc::IPPROTO_RAW => String::from("RAW"),
        _ => format!("NONE: {}", proto),
    }
}
