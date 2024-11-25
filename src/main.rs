extern crate pnet;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, Config, NetworkInterface};
use pnet::datalink::{DataLinkReceiver, DataLinkSender};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use machammer::dhcp_forge::forge_dhcp_discover;
use machammer::dhcp_parser::is_dhcp_offer;

const NO_PACKET_TIMEOUT: u64 = 5;
const WAIT_RETRY_1: Duration = Duration::from_secs(3);
const WAIT_RETRY_2: Duration = Duration::from_secs(9);
const WAIT_RETRY_3: Duration = Duration::from_secs(15);
const WAIT_OFFER: Duration = Duration::from_secs(21);

fn main() {
    let now = Instant::now();

    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        println!(
            "Usage: {} <NETWORK_INTERFACE> <MAC_LIST_FILE_PATH> <NUMBER_OF_THREAD>",
            args[0]
        );
        return;
    }

    let interface_name = args[1].clone();
    let mut mac_stack = get_mac_stack(&args[2]);
    let thread_limit: usize = args[3].to_string().parse().unwrap();

    let (tx, rx) = mpsc::channel();
    let mut thread_pool: HashMap<MacAddr, JoinHandle<_>> = HashMap::new();

    for _ in 0..thread_limit {
        (thread_pool, mac_stack) =
            new_thread(thread_pool, mac_stack, interface_name.clone(), tx.clone());

        if mac_stack.len() == 0 {
            break;
        }
    }

    while let Ok(mac) = rx.recv() {
        println!("| Removing {}", mac);
        thread_pool.remove(&mac);

        (thread_pool, mac_stack) =
            new_thread(thread_pool, mac_stack, interface_name.clone(), tx.clone());

        if mac_stack.len() == 0 {
            break;
        }
    }

    // ensure that the pool is really empty (should be at this point)
    for (mac, thread) in thread_pool {
        println!("| Cleaning {}", mac);
        let _ = thread.join();
        //thread_pool.remove(&mac);
    }

    // was ~ 66s without parallelisation
    // was ~ 21s without parallelisation
    println!("\nProgram took {}s to execute", now.elapsed().as_secs());
}

fn new_thread(
    mut thread_pool: HashMap<MacAddr, JoinHandle<()>>,
    mut mac_stack: Vec<MacAddr>,
    scoped_iface: String,
    scoped_tx: Sender<MacAddr>,
) -> (HashMap<MacAddr, JoinHandle<()>>, Vec<MacAddr>) {
    if let Some(scoped_mac) = mac_stack.pop() {
        println!("| Starting {}", scoped_mac);
        thread_pool.insert(
            scoped_mac.clone(),
            thread::spawn(move || {
                run(scoped_mac, get_interface(scoped_iface));
                let _ = scoped_tx.send(scoped_mac);
            }),
        );
    }

    (thread_pool, mac_stack)
}

fn build_channel(
    interface: NetworkInterface,
) -> (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>) {
    let mut config: Config = Default::default();
    config.read_timeout = Some(Duration::from_secs(NO_PACKET_TIMEOUT));

    match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the channel: {}", e),
    }
}

fn run(rogue_mac: MacAddr, interface: NetworkInterface) {
    const DHCP_DISCOVER_BUFFER_LENGTH: usize = 342;

    let (mut tx, mut rx) = build_channel(interface.clone());
    let buffer = &mut [0; DHCP_DISCOVER_BUFFER_LENGTH];
    let xid = rand::random();

    forge_dhcp_discover(rogue_mac, buffer, xid, 0);
    tx.send_to(buffer, Some(interface.clone()));

    let mut retry = 0;
    let start = Instant::now();

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();

                let check_mac = packet.get_destination() == rogue_mac;
                let check_type = packet.get_ethertype() == EtherTypes::Ipv4;
                let check_payload = is_dhcp_offer(packet.payload());

                if check_mac && check_type && check_payload {
                    println!("| > {} SUCCESS", rogue_mac);
                    break;
                }
            }
            Err(e) => {
                if e.kind() == ErrorKind::TimedOut {
                    panic!(
                        "WARNING : no packet received for some time, \
                             is your NIC working ?"
                    );
                } else {
                    panic!("An error occurred while reading: {}", e)
                }
            }
        }

        if start.elapsed() >= WAIT_OFFER && retry == 3 {
            println!("| > {} FAILURE", rogue_mac);
            break;
        } else if start.elapsed() >= WAIT_RETRY_3 && retry == 2 {
            forge_dhcp_discover(rogue_mac, buffer, xid, 12);
            tx.send_to(buffer, Some(interface.clone()));
            retry += 1;
        } else if start.elapsed() >= WAIT_RETRY_2 && retry == 1 {
            forge_dhcp_discover(rogue_mac, buffer, xid, 6);
            tx.send_to(buffer, Some(interface.clone()));
            retry += 1;
        } else if start.elapsed() >= WAIT_RETRY_1 && retry == 0 {
            forge_dhcp_discover(rogue_mac, buffer, xid, 3);
            tx.send_to(buffer, Some(interface.clone()));
            retry += 1;
        }
    }
}

fn get_interface(input: String) -> NetworkInterface {
    let is_iface = |iface: &NetworkInterface| iface.name == input;
    datalink::interfaces()
        .into_iter()
        .filter(is_iface)
        .next()
        .unwrap()
}

fn get_mac_stack(file_path: &String) -> Vec<MacAddr> {
    fs::read_to_string(file_path)
        .unwrap()
        .lines()
        .map(|l| {
            // transform each string octet of mac address into an u8
            let mut b: Vec<u8> = l
                .split(":")
                .map(|o| u8::from_str_radix(o, 16).unwrap())
                .collect();

            // if a range is given (len(mac) < 6b), we fill it with random values
            for _ in 0..(6 - b.len()) {
                b.push(rand::random());
            }

            MacAddr::new(b[0], b[1], b[2], b[3], b[4], b[5])
        })
        .collect()
}
