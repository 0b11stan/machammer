# MACHammer

A Media Access Contrôle ranges scan to find NAC bypasses

## Documentation

- [rust manual](https://doc.rust-lang.org/book/title-page.html)
- [rust pcap documentation](https://docs.rs/pcap/latest/pcap/)

## Usage

### Prod

Build the binary

```bash
cargo build --release
```

Allow the binary to listen to all packets and forge it's own packets

```bash
sudo setcap cap_net_raw,cap_net_admin=eip target/debug/machammer
```

Run the binary

```bash
./target/debug/machammer
```

### Dev

To run with libpcap privilege without being root:

```bash
nix-shell
./run.sh
```

For dev process (build every sec with color):

```bash
watch --color cargo --color=always build
```

## Notes

je ne comprend pas pourquoi mais parfois même avec une mac whitelisté eap envoie des trames d'authentification
cependant les requêtes dhcp fonctionnent quand même, c'est chelou
peut être un truc anti-detection, faut voir
mais du coup on est obliger d'attendre une vrai offre dhcp pour être sur de nous

pour tester

```
sudo macchanger --mac='00:21:B7:01:02:03' eth0
sudo dhcpcd --oneshot --nobackground
```

## Features

- [x] send a dhcp discover with rogue mac
- [x] randomize the non-vendor part of mac addresses
- [x] detect dhcp offers
- [x] timeout when no packet is received at all
- [x] compute real udp checksum
- [x] send multiple dhcp offer with waiting time
- [x] take a list of mac addresses as input
- [x] take a list of mac ranges as input
- [x] parrallelisation
- [x] use a dynamic and configurable pool for parrallelisation
- [ ] improve CLI
