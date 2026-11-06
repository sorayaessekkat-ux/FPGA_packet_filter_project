# Run the cocotb tests with:  make
SIM ?= ghdl
TOPLEVEL_LANG = vhdl
GHDL_ARGS += --std=08

# Order matters: a file must come after the files it uses.
VHDL_SOURCES = $(PWD)/../../rtl/header_parser.vhd \
               $(PWD)/../../rtl/filter_rules_pkg.vhd \
               $(PWD)/../../rtl/rule_engine.vhd \
               $(PWD)/../../rtl/packet_filter.vhd

COCOTB_TOPLEVEL = packet_filter
COCOTB_TEST_MODULES = test_packet_filter

include $(shell cocotb-config --makefiles)/Makefile.sim