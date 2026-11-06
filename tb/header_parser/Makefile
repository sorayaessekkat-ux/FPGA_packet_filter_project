# Run the cocotb tests with:  make
SIM ?= ghdl
TOPLEVEL_LANG = vhdl
GHDL_ARGS += --std=08

VHDL_SOURCES = $(PWD)/../../rtl/header_parser.vhd

COCOTB_TOPLEVEL = header_parser
COCOTB_TEST_MODULES = test_header_parser

include $(shell cocotb-config --makefiles)/Makefile.sim
