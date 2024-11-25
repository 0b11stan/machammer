use pnet::packet::dhcp::DhcpPacket;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

struct DHCPOption {
    opcode: u8,
    _length: usize,
    payload: Vec<u8>,
}

pub fn is_dhcp_offer(buffer: &[u8]) -> bool {
    const UDP_PROTO_CODE: u8 = 17;
    const DHCP_COOKIE_SIZE: usize = 4;
    const UDP_SERVER_PORT: u16 = 67;
    const UDP_CLIENT_PORT: u16 = 68;
    const DHCP_OPTION_CODE_FOR_MSG_TYPE: u8 = 53;
    const DHCP_MSG_TYPE_OFFER: u8 = 2;

    if let Some(p) = Ipv4Packet::new(buffer) {
        if p.get_next_level_protocol() == IpNextHeaderProtocol(UDP_PROTO_CODE) {
            if let Some(p) = UdpPacket::new(p.payload()) {
                let src_match = p.get_source() == UDP_SERVER_PORT;
                let dst_match = p.get_destination() == UDP_CLIENT_PORT;

                if src_match && dst_match {
                    if let Some(p) = DhcpPacket::new(p.payload()) {
                        // skipping the DHCP magic cookie
                        let payload = &p.payload()[DHCP_COOKIE_SIZE..];

                        for opt in parse_dhcp_options(payload) {
                            let match_option_code = opt.opcode == DHCP_OPTION_CODE_FOR_MSG_TYPE;
                            let match_option_value = opt.payload == [DHCP_MSG_TYPE_OFFER];

                            if match_option_code && match_option_value {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    false
}

fn parse_dhcp_options(buffer: &[u8]) -> Vec<DHCPOption> {
    const DHCP_OPTIONS_EOF: u8 = 0xff;

    let mut options = vec![];
    let mut i = 0;
    while i < buffer.len() {
        let op_code = buffer[i];

        if op_code == DHCP_OPTIONS_EOF {
            break;
        };

        let op_length: usize = buffer[i + 1].into();
        options.push(DHCPOption {
            opcode: op_code,
            _length: op_length,
            payload: buffer[i + 2..i + 2 + op_length].to_vec(),
        });
        i += op_length + 2;
    }
    options
}
