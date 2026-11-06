# Run the cocotb tests with:  make
SIM ?= ghdl
TOPLEVEL_LANG = vhdl
GHDL_ARGS += --std=08

VHDL_SOURCES = $(PWD)/../../rtl/counter.vhd

# cocotb 2.x names
COCOTB_TOPLEVEL = counter
COCOTB_TEST_MODULES = test_counter

include $(shell cocotb-config --makefiles)/Makefile.sim