# FPGA Packet Filter

A hardware packet filter written in VHDL-2008. It parses Ethernet/IPv4/UDP
headers on the fly and decides to accept or drop each packet in a fixed
number of clock cycles.

## Status
In progress — V1: header parser

## Planned features
- Streaming header parser (Ethernet, IPv4, UDP)
- Parallel rule matching (accept / drop)
- Per-rule packet counters and latency measurement
- Verification with cocotb + GHDL against a Python reference model
- Synthesis on an Intel Cyclone V (DE1-SoC) with Quartus

## Repository layout
- `rtl/` — VHDL source
- `tb/` — cocotb testbenches and Python reference model
- `scripts/` — helper scripts
- `docs/` — diagrams and results