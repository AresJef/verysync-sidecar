use std::collections::BTreeMap;
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant as WallClock};

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket,
};
use verysync_isolated_tun_peer::{calibrate, CASES, SAMPLE_SIZE};
use wintun::{Packet, Session};

type Report<T = ()> = Result<T, Box<dyn std::error::Error>>;
const PORT: u16 = 47529;

#[derive(Clone, Copy)]
struct Link {
    sender: IpAddress,
    receiver: IpAddress,
    prefix: u8,
}

const LINKS: [Link; 2] = [
    Link {
        sender: IpAddress::v4(192, 0, 2, 1),
        receiver: IpAddress::v4(192, 0, 2, 2),
        prefix: 30,
    },
    Link {
        sender: IpAddress::v6(0x2001, 0xdb8, 0x73f, 0x43, 0, 0, 0, 1),
        receiver: IpAddress::v6(0x2001, 0xdb8, 0x73f, 0x43, 0, 0, 0, 2),
        prefix: 64,
    },
];

impl Link {
    fn segment(self, frame: &[u8]) -> Option<(u16, u8, usize)> {
        let (class, segment) = match (self.sender, self.receiver) {
            (IpAddress::Ipv4(source), IpAddress::Ipv4(target)) => {
                let packet = Ipv4Packet::new_checked(frame).ok()?;
                if packet.version() != 4
                    || packet.src_addr() != source
                    || packet.dst_addr() != target
                    || packet.next_header() != IpProtocol::Tcp
                    || packet.more_frags()
                    || packet.frag_offset() != 0
                {
                    return None;
                }
                (packet.dscp() << 2, packet.payload())
            }
            (IpAddress::Ipv6(source), IpAddress::Ipv6(target)) => {
                let packet = Ipv6Packet::new_checked(frame).ok()?;
                if packet.version() != 6
                    || packet.src_addr() != source
                    || packet.dst_addr() != target
                    || packet.next_header() != IpProtocol::Tcp
                {
                    return None;
                }
                (packet.traffic_class() & 0xfc, packet.payload())
            }
            _ => return None,
        };
        let packet = TcpPacket::new_checked(segment).ok()?;
        (packet.dst_port() == PORT).then(|| (packet.src_port(), class, packet.payload().len()))
    }
}

#[derive(Default)]
struct Match {
    bytes: usize,
    packets: usize,
    classes: BTreeMap<u8, usize>,
}

struct Tun {
    session: Arc<Session>,
    link: Link,
    flows: BTreeMap<u16, Match>,
    failure: Option<wintun::Error>,
}

struct Received(Packet);

impl phy::RxToken for Received {
    fn consume<T, F: FnOnce(&[u8]) -> T>(self, fill: F) -> T {
        fill(self.0.bytes())
    }
}

struct SendPacket<'a> {
    session: &'a Arc<Session>,
    failure: &'a mut Option<wintun::Error>,
}

impl phy::TxToken for SendPacket<'_> {
    fn consume<T, F: FnOnce(&mut [u8]) -> T>(self, length: usize, fill: F) -> T {
        // The IP interface's configured MTU bounds every outgoing allocation.
        match self.session.allocate_send_packet(length as u16) {
            Ok(mut packet) => {
                let result = fill(packet.bytes_mut());
                self.session.send_packet(packet);
                result
            }
            Err(error) => {
                *self.failure = Some(error);
                fill(&mut vec![0; length])
            }
        }
    }
}

impl Device for Tun {
    type RxToken<'a> = Received;
    type TxToken<'a> = SendPacket<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Received, SendPacket<'_>)> {
        for _ in 0..64 {
            let packet = match self.session.try_receive() {
                Ok(packet) => packet?,
                Err(error) => {
                    self.failure = Some(error);
                    return None;
                }
            };
            let Some((source_port, class, size)) = self.link.segment(packet.bytes()) else {
                continue;
            };
            if size != 0 {
                let matched = self.flows.entry(source_port).or_default();
                matched.bytes += size;
                matched.packets += 1;
                *matched.classes.entry(class).or_default() += 1;
            }
            return Some((
                Received(packet),
                SendPacket {
                    session: &self.session,
                    failure: &mut self.failure,
                },
            ));
        }
        None
    }

    fn transmit(&mut self, _: Instant) -> Option<SendPacket<'_>> {
        Some(SendPacket {
            session: &self.session,
            failure: &mut self.failure,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }
}

fn receive_case(
    interface: &mut Interface,
    device: &mut Tun,
    (family, class): (u8, u8),
) -> Report<bool> {
    device.link = LINKS[usize::from(family == 6)];
    device.flows.clear();
    let mut sockets = SocketSet::new(Vec::new());
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; SAMPLE_SIZE]),
        tcp::SocketBuffer::new(vec![0; 1024]),
    );
    socket.listen((device.link.receiver, PORT))?;
    let handle = sockets.add(socket);
    let mut source_port = None;
    let mut sample = Vec::with_capacity(SAMPLE_SIZE);
    let mut checksum = None;
    let mut buffer = [0; 16 * 1024];
    let started = WallClock::now();

    while started.elapsed() < Duration::from_secs(40) {
        interface.poll(Instant::now(), device, &mut sockets);
        if let Some(error) = device.failure.take() {
            return Err(error.into());
        }
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        if source_port.is_none() && socket.state() == tcp::State::Established {
            let peer = socket
                .remote_endpoint()
                .ok_or("missing TCP source endpoint")?;
            if peer.addr != device.link.sender || socket.send_slice(&[1])? != 1 {
                return Err("TCP source or calibration readiness did not match".into());
            }
            source_port = Some(peer.port);
        }
        while socket.can_recv() {
            let count = socket.recv_slice(&mut buffer)?;
            if count == 0 || sample.len() + count > SAMPLE_SIZE {
                return Err("calibration data exceeded its exact bounds".into());
            }
            sample.extend_from_slice(&buffer[..count]);
        }
        if checksum.is_none() && socket.state() == tcp::State::CloseWait {
            let digest =
                calibrate(family, class, &sample).ok_or("calibration sample was not exact")?;
            if socket.send_slice(&digest)? != digest.len() {
                return Err("independent TCP response was incomplete".into());
            }
            checksum = Some(digest);
            socket.close();
        }
        if let Some(digest) = checksum.filter(|_| socket.state() == tcp::State::Closed) {
            let port = source_port.ok_or("missing established calibration flow")?;
            let matched = device
                .flows
                .get(&port)
                .filter(|row| row.bytes >= SAMPLE_SIZE && row.packets > 0)
                .ok_or("missing full-size observed TCP data for the exact source port")?;
            let accepted =
                matched.classes.contains_key(&class) && (class != 0 || matched.classes.len() == 1);
            println!(
                "ARM64_TUN_QOS_DATA family={family} requested={class} source_port={port} bytes={} packets={} tcp_bytes={} octets={:?} sha256={digest:02x?} expected_octet_seen={accepted}",
                sample.len(), matched.packets, matched.bytes, matched.classes
            );
            return Ok(accepted);
        }
        thread::sleep(Duration::from_millis(1));
    }
    Err(format!("timeout observing complete TCP calibration for IPv{family} class {class}").into())
}

pub fn run() -> Report {
    if !cfg!(target_arch = "aarch64")
        || env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || env::var("GITHUB_REPOSITORY").as_deref() != Ok("AresJef/verysync-sidecar")
        || env::var("GITHUB_REF").as_deref() != Ok("refs/heads/verify/r24/windows-arm64-tun-data")
    {
        return Err("use only the assigned disposable native Windows ARM64 job".into());
    }
    let mut args = env::args_os().skip(1);
    let path = PathBuf::from(args.next().ok_or("missing private DLL path")?);
    let adapter_name = args
        .next()
        .and_then(|name| name.into_string().ok())
        .ok_or("missing exact owned adapter name")?;
    if !path.is_absolute()
        || path.file_name().and_then(|part| part.to_str()) != Some("wintun.dll")
        || !adapter_name.starts_with("VS-Wintun-")
        || args.next().is_some()
    {
        return Err("invalid owned Wintun fixture options".into());
    }
    // Only the owner passes the exact archive- and signature-checked DLL path.
    let library = unsafe { wintun::load_from_path(&path)? };
    let adapter = wintun::Adapter::open(&library, &adapter_name)?;
    let mut device = Tun {
        session: Arc::new(adapter.start_session(4 * 1024 * 1024)?),
        link: LINKS[0],
        flows: BTreeMap::new(),
        failure: None,
    };
    let mut interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        Instant::now(),
    );
    let mut both_ips_added = false;
    interface.update_ip_addrs(|addresses| {
        both_ips_added = LINKS.iter().all(|link| {
            addresses
                .push(IpCidr::new(link.receiver, link.prefix))
                .is_ok()
        })
    });
    if !both_ips_added {
        return Err("the owned layer-3 peer needs both isolated endpoints".into());
    }
    println!("ARM64_TUN_TCP_READY");
    io::stdout().flush()?;
    let mut all_matched = true;
    for case in CASES {
        all_matched &= receive_case(&mut interface, &mut device, case)?;
    }
    if !all_matched {
        return Err("one or more original qWAVE octets were absent from actual TCP data".into());
    }
    println!("ARM64_TUN_QOS_COMPLETE six_native_tcp_data_cases=true");
    Ok(())
}
