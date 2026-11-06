# FPGA packet filter

![tests](https://github.com/sorayaessekkat-ux/FPGA_packet_filter_project/actions/workflows/tests.yml/badge.svg)

A small hardware firewall in VHDL. Packets come in one byte per clock cycle. The circuit pulls
out the IP addresses, protocol and destination port, compares them with a list of rules and
decides whether the packet should be dropped.

I started this project to go beyond my digital logic course and to learn how FPGAs are used
for network processing, where a decision has to be made as the packet goes by and in a fixed time.

## How it works

```
bytes in -> header_parser -> rule_engine -> accept / drop
                                         -> accepted / dropped counters
```

- `header_parser` counts the incoming bytes and keeps the ones it needs: EtherType, IP protocol,
  source and destination addresses, ports. One cycle after byte 37, the header is complete.
- `rule_engine` checks the header against 8 rules at once. If several rules match, the lowest
  number wins. If none matches, the packet is accepted.
- `packet_filter` connects the two and counts accepted and dropped packets.

The decision always comes out 2 clock cycles after the last header byte, whatever the packet.

## Rules used in the tests

The rule set in `rtl/filter_rules_pkg.vhd` protects an example server network (192.168.1.0/24):

0. drop everything coming from 203.0.113.0/24
1. drop Telnet (TCP port 23)
2. accept SSH (TCP port 22) from 192.168.1.0/24
3. drop SSH from anywhere else
4. drop UDP sent to ports 1024-65535 of the web server 192.168.1.100

Order matters: SSH coming from 203.0.113.0/24 hits rule 0 first, so it is dropped even though
rules 2 and 3 also look at SSH.

## Testing

The tests use cocotb with the GHDL simulator. Packets are built with Scapy, so the parser sees
real Ethernet frames. Each decision from the hardware is compared with a short Python model
of the same rules.

The main test sends 600 packets with random gaps between bytes: 300 normal ones (web traffic,
admin SSH, DNS queries) and 300 attack packets (traffic from the blocked network, a UDP flood,
SSH attempts from the internet). Result:

- 300/300 attack packets dropped
- 0/300 legitimate packets dropped
- 2-cycle latency for every packet (20 ns with a 100 MHz clock)

The parser has its own tests (UDP, TCP, ARP, 200 random packets back to back), and GitHub
Actions runs everything on each push.

To run them, you need GHDL, Python, cocotb and Scapy:

```
pip install cocotb scapy
cd tb/packet_filter
make
```

## Limitations

- Only Ethernet II frames without VLAN tag and IPv4 headers of 20 bytes. Anything else is
  marked as unsupported and let through.
- The rules are fixed at synthesis time.
- So far it has only been run in simulation.

## Next

- Synthesis in Quartus for the Cyclone V of a DE1-SoC board (resource usage, maximum frequency)
- A demo on the board: packets replayed from on-chip memory, counters on the 7-segment
  displays, rules turned on and off with the switches
- Rules that can be changed while the circuit runs

## Layout

```
rtl/                VHDL source
tb/                 cocotb testbenches, one folder per module
.github/workflows/  automatic tests
```