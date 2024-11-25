use core::net::Ipv4Addr;
use pnet::packet::dhcp::DhcpHardwareType;
use pnet::packet::dhcp::DhcpOperation;
use pnet::packet::dhcp::MutableDhcpPacket;
use pnet::packet::ethernet::{EtherType, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::util::MacAddr;

pub fn forge_dhcp_discover(source_mac: MacAddr, buffer: &mut [u8], xid: u32, secs: u16) {
    let dhcp_buffer = &mut [0; 300];
    let udp_buffer = &mut [0; 308];
    let ip_buffer = &mut [0; 328];

    forge_dhcp_packet(dhcp_buffer, source_mac, xid, secs);
    forge_udp_packet(udp_buffer, dhcp_buffer);
    forge_ip_packet(ip_buffer, udp_buffer);
    forge_eth_packet(buffer, source_mac, ip_buffer);
}

fn forge_dhcp_packet(buffer: &mut [u8], source_mac: MacAddr, xid: u32, secs: u16) {
    let mut packet = MutableDhcpPacket::new(buffer).unwrap();
    packet.set_op(DhcpOperation(1));
    packet.set_htype(DhcpHardwareType(1));
    packet.set_hlen(6);
    packet.set_hops(0);
    packet.set_xid(xid);
    packet.set_secs(secs);
    packet.set_flags(0);
    packet.set_ciaddr(Ipv4Addr::new(0, 0, 0, 0));
    packet.set_yiaddr(Ipv4Addr::new(0, 0, 0, 0));
    packet.set_siaddr(Ipv4Addr::new(0, 0, 0, 0));
    packet.set_giaddr(Ipv4Addr::new(0, 0, 0, 0));
    packet.set_chaddr(source_mac);
    packet.set_chaddr_pad(&[0; 10]);
    packet.set_sname(&[0; 64]);
    packet.set_file(&[0; 128]);
    packet.set_options(&[
        0x63, 0x82, 0x53, 0x63, // Magic cookie: DHCP
        0x35, 0x01, 0x01, // Option: (53) DHCP Message Type (Discover)
        0x0c, 0x11, 0x44, 0x43, 0x53, 0x2d, 0x43, 0x59, 0x42, 0x45, 0x52, 0x41, 0x54, 0x54, 0x41,
        0x51, 0x55, 0x45, 0x34, // Option: (12) Host Name
        0x37, 0x0d, 0x01, 0x1c, 0x02, 0x03, 0x0f, 0x06, 0x77, 0x0c, 0x2c, 0x2f, 0x1a, 0x79,
        0x2a, // Option: (55) Parameter Request List
        0xff, // Option: (255) End
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
}

fn forge_udp_packet(buffer: &mut [u8], payload: &[u8]) {
    let length = buffer.len() as u16;
    let mut packet = MutableUdpPacket::new(buffer).unwrap();
    packet.set_source(68);
    packet.set_destination(67);
    packet.set_length(length);
    packet.set_checksum(forge_udp_checksum_for_dhcp_discover(payload));
    packet.set_payload(payload);
}

fn forge_udp_checksum_for_dhcp_discover(payload: &[u8]) -> u16 {
    /* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
     *                                                                 *
     *  To understand this crap, read CAREFULLY the RFC 768 and 1071.  *
     *                                                                 *
     * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

    const UDP_HEADER_SIZE: u16 = 8;
    const UDP_PROTO_CODE: u16 = 17;

    let length: u16 = payload.len() as u16;

    let end_around_carry_sum = |a: u16, b: u16| -> u16 {
        let (c, d) = a.overflowing_add(b);
        return c + d as u16;
    };

    let mut sum = 0;

    // PSEUDO IP HEADER //

    sum = end_around_carry_sum(sum, 0x0000); // src addr (1/2) : 255.255
    sum = end_around_carry_sum(sum, 0x0000); // src addr (2/2) : 255.255
    sum = end_around_carry_sum(sum, 0xffff); // dst addr (1/2) : 0.0
    sum = end_around_carry_sum(sum, 0xffff); // dst addr (2/2) : 0.0
    sum = end_around_carry_sum(sum, UDP_PROTO_CODE);
    sum = end_around_carry_sum(sum, length + UDP_HEADER_SIZE);

    // UDP HEADER //

    sum = end_around_carry_sum(sum, 0x0044); // src port : 68
    sum = end_around_carry_sum(sum, 0x0043); // dst port : 67
    sum = end_around_carry_sum(sum, length + UDP_HEADER_SIZE);
    sum = end_around_carry_sum(sum, 0x0000); // udp checksum placeholder

    // UDP PAYLOAD //

    let mut i: usize = 0;
    while i < (length - (length % 2)).into() {
        let chunk: &[u8] = &payload[i..i + 2];
        let number = ((chunk[0] as u16) << 8) | (chunk[1] as u16);
        sum = end_around_carry_sum(sum, number);
        i += 2;
    }

    // handle cases where number of bytes is odd
    if length % 2 != 0 {
        let number = (payload[(length as usize) - 1] as u16) << 8;
        sum = end_around_carry_sum(sum, number);
    }

    // a way of doing the one's complement (see RFC 768 and RFC 1071)
    return u16::MAX - sum;
}

fn forge_ip_packet(buffer: &mut [u8], payload: &[u8]) {
    let mut packet = MutableIpv4Packet::new(buffer).unwrap();
    packet.set_version(4);
    packet.set_header_length(5);
    packet.set_dscp(4);
    packet.set_ecn(0);
    packet.set_total_length(328);
    packet.set_identification(0);
    packet.set_flags(0);
    packet.set_fragment_offset(0);
    packet.set_ttl(128);
    packet.set_next_level_protocol(IpNextHeaderProtocol(17));
    packet.set_checksum(0x3996);
    packet.set_source(Ipv4Addr::new(0, 0, 0, 0));
    packet.set_destination(Ipv4Addr::new(255, 255, 255, 255));
    packet.set_options(&[]);
    packet.set_payload(payload);
}

fn forge_eth_packet(buffer: &mut [u8], source_mac: MacAddr, payload: &[u8]) {
    let mut packet = MutableEthernetPacket::new(buffer).unwrap();
    packet.set_destination(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
    packet.set_source(source_mac);
    packet.set_ethertype(EtherType::new(0x800));
    packet.set_payload(payload);
}
