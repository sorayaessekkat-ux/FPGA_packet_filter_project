"""cocotb tests for rtl/counter.vhd"""
import cocotb
from cocotb.triggers import Timer, RisingEdge, FallingEdge


async def generate_clock(clk, period_ns=10):
    """Drive a 100 MHz clock (period 10 ns) forever."""
    while True:
        clk.value = 0
        await Timer(period_ns // 2, "ns")
        clk.value = 1
        await Timer(period_ns // 2, "ns")


async def reset(dut):
    """Hold reset high for 2 clock cycles."""
    dut.rst.value = 1
    dut.en.value = 0
    for _ in range(2):
        await RisingEdge(dut.clk)
    dut.rst.value = 0
    await FallingEdge(dut.clk)


@cocotb.test()
async def test_counts_up(dut):
    """After reset, the counter increases by 1 on each clock edge."""
    cocotb.start_soon(generate_clock(dut.clk))
    await reset(dut)
    assert int(dut.count.value) == 0, "count should be 0 after reset"

    dut.en.value = 1
    for expected in range(1, 11):
        await RisingEdge(dut.clk)
        await FallingEdge(dut.clk)
        assert int(dut.count.value) == expected, (
            f"expected {expected}, got {int(dut.count.value)}"
        )


@cocotb.test()
async def test_enable_low_holds_value(dut):
    """When en = 0, the counter keeps its value."""
    cocotb.start_soon(generate_clock(dut.clk))
    await reset(dut)

    dut.en.value = 1
    for _ in range(5):
        await RisingEdge(dut.clk)
    await FallingEdge(dut.clk)
    value = int(dut.count.value)

    dut.en.value = 0
    for _ in range(5):
        await RisingEdge(dut.clk)
    await FallingEdge(dut.clk)
    assert int(dut.count.value) == value, "count changed while en = 0"


@cocotb.test()
async def test_wraps_around(dut):
    """After 255, the 8-bit counter goes back to 0."""
    cocotb.start_soon(generate_clock(dut.clk))
    await reset(dut)

    dut.en.value = 1
    for _ in range(256):
        await RisingEdge(dut.clk)
    await FallingEdge(dut.clk)
    assert int(dut.count.value) == 0, "counter should wrap to 0 after 255"