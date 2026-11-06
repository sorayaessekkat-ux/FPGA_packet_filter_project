"""cocotb tests for rtl/packet_filter.vhd (parser + rule engine + counters).

A Python reference model applies the same rules as rtl/filter_rules_pkg.vhd.
Every decision of the hardware is compared with the model.
"""
import ipaddress
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

SERVER = "192.168.1.100"   # the web server we protect
LATENCY = 2                # cycles between the last header byte and the decision


# ------------------------------------------------------- reference model
# Same rules as rtl/filter_rules_pkg.vhd, in the same order.
# (source network, destination network, protocol, port range, drop?)
RULES = [
    ("203.0.113.0/24", "0.0.0.0/0", None, (0, 65535), True),        # 0
    ("0.0.0.0/0", "0.0.0.0/0", "tcp", (23, 23), True),              # 1
    ("192.168.1.0/24", "0.0.0.0/0", "tcp", (22, 22), False),        # 2
    ("0.0.0.0/0", "0.0.0.0/0", "tcp", (22, 22), True),              # 3
    ("0.0.0.0/0", SERVER + "/32", "udp", (1024, 65535), True),      # 4
]


def model_decision(pkt):
    """Return (drop, rule_hit, rule_index) for a Scapy packet."""
    if IP not in pkt or (TCP not in pkt and UDP not in pkt):
        return (False, False, 0)          # not IPv4 TCP/UDP: default accept
    src = ipaddress.ip_address(pkt[IP].src)
    dst = ipaddress.ip_address(pkt[IP].dst)
    proto = "tcp" if TCP in pkt else "udp"
    dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
    for index, (src_net, dst_net, rule_proto, (lo, hi), drop) in enumerate(RULES):
        if (src in ipaddress.ip_network(src_net)
                and dst in ipaddress.ip_network(dst_net)
                and rule_proto in (None, proto)
                and lo <= dport <= hi):
            return (drop, True, index)    # first matching rule wins
    return (False, False, 0)              # no rule: default accept


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


class Bench:
    """Drives packets into the filter and records its decisions."""

    def __init__(self, dut):
        self.dut = dut
        self.cycle = 0
        self.header_end_cycles = []   # cycle at which byte 37 was sent
        self.decisions = []           # (drop, hit, index, cycle)

    async def start(self):
        cocotb.start_soon(generate_clock(self.dut.clk))
        await reset(self.dut)
        await FallingEdge(self.dut.clk)
        cocotb.start_soon(self._count_cycles())
        cocotb.start_soon(self._monitor())

    async def _count_cycles(self):
        """Count clock cycles (rising edges) to measure the latency."""
        while True:
            await RisingEdge(self.dut.clk)
            self.cycle += 1

    async def _monitor(self):
        while True:
            await FallingEdge(self.dut.clk)
            if self.dut.decision_valid.value == 1:
                self.decisions.append((
                    int(self.dut.decision_drop.value) == 1,
                    int(self.dut.rule_hit.value) == 1,
                    int(self.dut.rule_index.value),
                    self.cycle,
                ))

    async def send(self, pkt, gap_probability=0.0):
        data = raw(pkt)
        dut = self.dut
        for i, byte in enumerate(data):
            while random.random() < gap_probability:
                dut.in_valid.value = 0
                await FallingEdge(dut.clk)
            dut.in_valid.value = 1
            dut.in_data.value = byte
            dut.in_last.value = 1 if i == len(data) - 1 else 0
            if i == 37:
                self.header_end_cycles.append(self.cycle)
            await FallingEdge(dut.clk)
        dut.in_valid.value = 0
        dut.in_last.value = 0

    async def finish(self):
        for _ in range(LATENCY + 2):
            await FallingEdge(self.dut.clk)


def eth():
    return Ether(dst=DST_MAC, src=SRC_MAC)


def random_public_ip():
    """A random internet address outside the blocked and private networks."""
    while True:
        ip = ipaddress.ip_address(random.randint(0x01000000, 0xDFFFFFFF))
        if ip.is_global and ip not in ipaddress.ip_network("203.0.113.0/24"):
            return str(ip)


def check_against_model(bench, packets):
    assert len(bench.decisions) == len(packets), (
        f"sent {len(packets)} packets, got {len(bench.decisions)} decisions")
    for i, (pkt, decision) in enumerate(zip(packets, bench.decisions)):
        drop, hit, index, cycle = decision
        expected = model_decision(pkt)
        assert (drop, hit, index if hit else 0) == expected, (
            f"packet {i} ({pkt.summary()}): got drop={drop} hit={hit} rule={index}, "
            f"expected drop={expected[0]} hit={expected[1]} rule={expected[2]}")
        latency = cycle - bench.header_end_cycles[i]
        assert latency == LATENCY, f"packet {i}: latency {latency} cycles, expected {LATENCY}"


# ------------------------------------------------------------------ tests
@cocotb.test()
async def test_each_rule(dut):
    """One packet for each rule, plus the cases where rule order matters."""
    bench = Bench(dut)
    await bench.start()

    cases = [
        # (packet, expected drop, expected rule or None)
        (eth() / IP(src="203.0.113.66", dst=SERVER) / TCP(dport=443), True, 0),
        (eth() / IP(src="8.8.4.4", dst=SERVER) / TCP(dport=23), True, 1),
        (eth() / IP(src="192.168.1.20", dst=SERVER) / TCP(dport=22), False, 2),
        (eth() / IP(src="8.8.4.4", dst=SERVER) / TCP(dport=22), True, 3),
        (eth() / IP(src="8.8.4.4", dst=SERVER) / UDP(dport=5000), True, 4),
        # no rule matches: accepted
        (eth() / IP(src="8.8.4.4", dst=SERVER) / TCP(dport=443), False, None),
        (eth() / ARP(pdst="192.168.1.1"), False, None),
        # order matters: rule 0 wins over rule 3, rule 1 wins over rule 2
        (eth() / IP(src="203.0.113.5", dst=SERVER) / TCP(dport=22), True, 0),
        (eth() / IP(src="192.168.1.20", dst=SERVER) / TCP(dport=23), True, 1),
    ]
    packets = [pkt for pkt, _, _ in cases]
    for pkt in packets:
        await bench.send(pkt)
    await bench.finish()

    for i, ((pkt, drop, rule), (got_drop, got_hit, got_index, _)) in enumerate(
            zip(cases, bench.decisions)):
        assert got_drop == drop, f"case {i} ({pkt.summary()}): drop={got_drop}, expected {drop}"
        if rule is None:
            assert not got_hit, f"case {i}: no rule should match"
        else:
            assert got_hit and got_index == rule, f"case {i}: rule {got_index}, expected {rule}"
    check_against_model(bench, packets)

    dropped = sum(1 for _, drop, _ in cases if drop)
    assert int(dut.cnt_dropped.value) == dropped
    assert int(dut.cnt_accepted.value) == len(cases) - dropped


@cocotb.test()
async def test_attack_scenario(dut):
    """Normal traffic to the server, mixed with three kinds of attack.

    Every attack packet must be dropped and no legitimate packet lost.
    """
    random.seed(2026)
    bench = Bench(dut)
    await bench.start()

    legit, attack = [], []
    for _ in range(300):
        kind = random.random()
        if kind < 0.7:    # visitors of the website (HTTPS / HTTP)
            pkt = eth() / IP(src=random_public_ip(), dst=SERVER) / TCP(
                sport=random.randint(1024, 65535), dport=random.choice([443, 80]))
        elif kind < 0.85: # administrators connecting with SSH
            pkt = eth() / IP(src=f"192.168.1.{random.randint(2, 99)}", dst=SERVER) / TCP(
                sport=random.randint(1024, 65535), dport=22)
        else:             # the server asking a DNS question
            pkt = eth() / IP(src=SERVER, dst="8.8.8.8") / UDP(
                sport=random.randint(1024, 65535), dport=53)
        legit.append(pkt)

    for _ in range(300):
        kind = random.random()
        if kind < 0.4:    # traffic from the blocked network
            pkt = eth() / IP(src=f"203.0.113.{random.randint(1, 254)}", dst=SERVER) / TCP(
                dport=443)
        elif kind < 0.7:  # UDP flood on random high ports of the server
            pkt = eth() / IP(src=random_public_ip(), dst=SERVER) / UDP(
                dport=random.randint(1024, 65535))
        else:             # SSH password guessing from the internet
            pkt = eth() / IP(src=random_public_ip(), dst=SERVER) / TCP(dport=22)
        attack.append(pkt)

    traffic = [(pkt, False) for pkt in legit] + [(pkt, True) for pkt in attack]
    random.shuffle(traffic)
    packets = []
    for pkt, _ in traffic:
        pkt = pkt / bytes(random.randint(0, 255) for _ in range(random.randint(0, 30)))
        packets.append(pkt)
        await bench.send(pkt, gap_probability=0.1)
    await bench.finish()

    check_against_model(bench, packets)

    attack_dropped = sum(1 for (_, is_attack), d in zip(traffic, bench.decisions) if is_attack and d[0])
    legit_dropped = sum(1 for (_, is_attack), d in zip(traffic, bench.decisions) if not is_attack and d[0])
    dut._log.info(
        f"Attack packets dropped: {attack_dropped}/{len(attack)} | "
        f"legitimate packets lost: {legit_dropped}/{len(legit)} | "
        f"decision latency: {LATENCY} cycles ({LATENCY * 10} ns at 100 MHz)")

    assert attack_dropped == len(attack), "some attack packets got through"
    assert legit_dropped == 0, "some legitimate packets were dropped"
    assert int(dut.cnt_dropped.value) == len(attack)
    assert int(dut.cnt_accepted.value) == len(legit)