//! How a browse reads its two sockets.

use std::net::{Ipv4Addr, UdpSocket};
use std::time::{Duration, Instant};

use super::{BrowseSockets, MDNS_POLL, MDNS_SOCKET_POLL};

/// How long a test waits for a datagram it sent to itself.
const ARRIVAL: Duration = Duration::from_secs(5);
/// Quiet rounds measured together, so one late timer does not decide.
const QUIET_ROUNDS: u32 = 4;
/// A datagram on the busy socket.
const NOISE: &[u8] = b"noise";
/// The datagram on the quiet socket.
const ANSWER: &[u8] = b"answer";
/// Largest test datagram.
const BUFFER_BYTES: usize = 16;

fn bound() -> UdpSocket {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    socket
        .set_read_timeout(Some(MDNS_SOCKET_POLL))
        .expect("timeout");
    socket
}

fn sockets() -> BrowseSockets {
    BrowseSockets::over(Some(bound()), bound())
}

fn send(to: &UdpSocket, payload: &[u8]) {
    let from = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    from.send_to(payload, to.local_addr().expect("address"))
        .expect("send");
}

#[test]
fn a_quiet_round_takes_one_poll_and_not_one_per_socket() {
    let sockets = sockets();
    let mut buffer = [0u8; BUFFER_BYTES];
    let started = Instant::now();
    for _ in 0..QUIET_ROUNDS {
        assert!(sockets.receive(&mut buffer).is_none());
    }
    // One poll per socket would take twice one poll a round; none would not
    // wait at all.
    let one_poll_each = MDNS_POLL * QUIET_ROUNDS;
    let took = started.elapsed();
    assert!(took < one_poll_each * 3 / 2, "took {took:?}");
    assert!(took > one_poll_each / 2, "took {took:?}");
}

#[test]
fn multicast_traffic_does_not_hold_back_a_unicast_answer() {
    let sockets = sockets();
    let group = sockets.group.as_ref().expect("a group socket");
    send(group, NOISE);
    send(group, NOISE);
    send(group, NOISE);
    send(&sockets.legacy, ANSWER);
    // Both sockets hold a datagram once this returns.
    std::thread::sleep(MDNS_POLL);
    let started = Instant::now();
    let mut buffer = [0u8; BUFFER_BYTES];
    let mut heard = Vec::new();
    while heard.len() < 2 && started.elapsed() < ARRIVAL {
        if let Some((read, _peer)) = sockets.receive(&mut buffer) {
            heard.push(buffer[..read].to_vec());
        }
    }
    assert!(
        heard.iter().any(|payload| payload == ANSWER),
        "the answer waited behind the noise: {heard:?}"
    );
}
