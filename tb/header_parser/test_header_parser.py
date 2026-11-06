"""cocotb tests for rtl/header_parser.vhd

Packets are built with Scapy, sent byte by byte to the parser, and the
fields read back from the parser are compared with what Scapy put in.
"""
import random

import cocotb
from cocotb.triggers import FallingEdge, RisingEdge, Timer

import logging
logging.getLogger("scapy").setLevel(logging.ERROR)  # hide Scapy warnings (no IPv6 in this Python)

from scapy.compat import raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

DST_MAC = "a4:83:e7:12:34:56"
SRC_MAC = "3c:22:fb:ab:cd:ef"


# ---------------------------------------------------------------- helpers
async def generate_clock(clk, period_ns=10):
    while True:
        clk.value = 0
        await Timer(period_ns // 2, "ns")
        clk.value = 1
        await Timer(period_ns // 2, "ns")


async def reset(dut):
    dut.rst.value = 1
    dut.in_valid.value = 0
    dut.in_data.value = 0
    dut.in_last.value = 0
    for _ in range(2):
        await RisingEdge(dut.clk)
    dut.rst.value = 0


async def send_packet(dut, data: bytes, gap_probability=0.0):
    """Send one packet, one byte per clock cycle.

    With gap_probability > 0, random idle cycles (in_valid = 0) are
    inserted between bytes, like a real link that is not always busy.
    """
    for i, byte in enumerate(data):
        while random.random() < gap_probability:
            dut.in_valid.value = 0
            await FallingEdge(dut.clk)
        dut.in_valid.value = 1
        dut.in_data.value = byte
        dut.in_last.value = 1 if i == len(data) - 1 else 0
        await FallingEdge(dut.clk)
    dut.in_valid.value = 0
    dut.in_last.value = 0


async def collect_headers(dut, results):
    """Background task: record the fields every time hdr_valid = 1."""
    while True:
        await FallingEdge(dut.clk)
        if dut.hdr_valid.value == 1:
            results.append({
                "ethertype": int(dut.ethertype.value),
                "ip_proto": int(dut.ip_proto.value),
                "ip_src": int(dut.ip_src.value),
                "ip_dst": int(dut.ip_dst.value),
                "port_src": int(dut.port_src.value),
                "port_dst": int(dut.port_dst.value),
                "supported": int(dut.hdr_supported.value),
            })


def ip_to_int(ip: str) -> int:
    a, b, c, d = (int(x) for x in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def expected_fields(pkt) -> dict:
    """What the parser should output for a Scapy packet."""
    l4 = pkt[UDP] if UDP in pkt else pkt[TCP]
    return {
        "ethertype": 0x0800,
        "ip_proto": pkt[IP].proto,
        "ip_src": ip_to_int(pkt[IP].src),
        "ip_dst": ip_to_int(pkt[IP].dst),
        "port_src": l4.sport,
        "port_dst": l4.dport,
        "supported": 1,
    }


async def start(dut):
    """Start the clock, reset the parser and start the collector."""
    cocotb.start_soon(generate_clock(dut.clk))
    await reset(dut)
    await FallingEdge(dut.clk)
    results = []
    cocotb.start_soon(collect_headers(dut, results))
    return results


# ------------------------------------------------------------------ tests
@cocotb.test()
async def test_udp_dns_query(dut):
    """A DNS query (UDP) to 8.8.8.8 port 53."""
    results = await start(dut)
    pkt = Ether(dst=DST_MAC, src=SRC_MAC) / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=51000, dport=53) / b"hello"

    await send_packet(dut, raw(pkt))
    await FallingEdge(dut.clk)

    assert len(results) == 1, f"expected 1 header, got {len(results)}"
    assert results[0] == expected_fields(pkt)


@cocotb.test()
async def test_tcp_https(dut):
    """A TCP packet to a web server on port 443."""
    results = await start(dut)
    pkt = Ether(dst=DST_MAC, src=SRC_MAC) / IP(src="10.0.0.5", dst="142.250.65.78") / TCP(sport=60123, dport=443) / b"GET /"

    await send_packet(dut, raw(pkt))
    await FallingEdge(dut.clk)

    assert len(results) == 1
    assert results[0] == expected_fields(pkt)


@cocotb.test()
async def test_non_ipv4_is_not_supported(dut):
    """An ARP packet is not IPv4: hdr_supported must be 0."""
    results = await start(dut)
    pkt = Ether(dst=DST_MAC, src=SRC_MAC) / ARP(pdst="192.168.1.1")

    await send_packet(dut, raw(pkt))
    await FallingEdge(dut.clk)

    assert len(results) == 1
    assert results[0]["ethertype"] == 0x0806
    assert results[0]["supported"] == 0


@cocotb.test()
async def test_many_random_packets_with_gaps(dut):
    """200 random UDP/TCP packets back to back, with random idle cycles."""
    random.seed(1)
    results = await start(dut)

    sent = []
    for _ in range(200):
        src = ".".join(str(random.randint(1, 254)) for _ in range(4))
        dst = ".".join(str(random.randint(1, 254)) for _ in range(4))
        sport, dport = random.randint(1, 65535), random.randint(1, 65535)
        l4 = UDP(sport=sport, dport=dport) if random.random() < 0.5 else TCP(sport=sport, dport=dport)
        payload = bytes(random.randint(0, 255) for _ in range(random.randint(0, 40)))
        pkt = Ether(dst=DST_MAC, src=SRC_MAC) / IP(src=src, dst=dst) / l4 / payload
        sent.append(pkt)
        await send_packet(dut, raw(pkt), gap_probability=0.2)

    await FallingEdge(dut.clk)

    assert len(results) == len(sent), f"sent {len(sent)} packets, parsed {len(results)}"
    for i, (got, pkt) in enumerate(zip(results, sent)):
        assert got == expected_fields(pkt), f"packet {i}: got {got}, expected {expected_fields(pkt)}"