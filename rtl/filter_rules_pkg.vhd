-- Rule table of the packet filter.
--
-- Each rule compares the parsed header fields with a pattern.
-- The rules are checked all at the same time; when several rules match,
-- the one with the lowest index wins. If no rule matches, the packet is
-- accepted (DEFAULT_DROP = false).
--
-- Example rule set ("protect a small server network 192.168.1.0/24"):
--   0  drop   everything from the blocked network 203.0.113.0/24
--   1  drop   Telnet (TCP port 23), an old insecure protocol
--   2  accept SSH (TCP port 22) from the admin network 192.168.1.0/24
--   3  drop   SSH from anywhere else
--   4  drop   UDP to ports 1024-65535 of the web server 192.168.1.100
--   5-7 unused
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

package filter_rules_pkg is

  constant NUM_RULES    : natural := 8;
  constant DEFAULT_DROP : boolean := false;

  constant PROTO_TCP : std_logic_vector(7 downto 0) := x"06";
  constant PROTO_UDP : std_logic_vector(7 downto 0) := x"11";

  type rule_t is record
    enabled   : boolean;
    src_ip    : std_logic_vector(31 downto 0);
    src_mask  : std_logic_vector(31 downto 0);   -- x"00000000" = any source
    dst_ip    : std_logic_vector(31 downto 0);
    dst_mask  : std_logic_vector(31 downto 0);   -- x"00000000" = any destination
    proto_any : boolean;
    proto     : std_logic_vector(7 downto 0);
    dport_lo  : natural range 0 to 65535;        -- destination port range
    dport_hi  : natural range 0 to 65535;
    drop      : boolean;                         -- true = drop, false = accept
  end record;

  type rule_table_t is array (0 to NUM_RULES - 1) of rule_t;

  constant UNUSED_RULE : rule_t := (
    enabled => false,
    src_ip => x"00000000", src_mask => x"00000000",
    dst_ip => x"00000000", dst_mask => x"00000000",
    proto_any => true, proto => x"00",
    dport_lo => 0, dport_hi => 65535,
    drop => false);

  constant RULES : rule_table_t := (
    -- 0: drop everything from 203.0.113.0/24
    0 => (enabled => true,
          src_ip => x"CB007100", src_mask => x"FFFFFF00",
          dst_ip => x"00000000", dst_mask => x"00000000",
          proto_any => true, proto => x"00",
          dport_lo => 0, dport_hi => 65535,
          drop => true),
    -- 1: drop Telnet
    1 => (enabled => true,
          src_ip => x"00000000", src_mask => x"00000000",
          dst_ip => x"00000000", dst_mask => x"00000000",
          proto_any => false, proto => PROTO_TCP,
          dport_lo => 23, dport_hi => 23,
          drop => true),
    -- 2: accept SSH from the admin network 192.168.1.0/24
    2 => (enabled => true,
          src_ip => x"C0A80100", src_mask => x"FFFFFF00",
          dst_ip => x"00000000", dst_mask => x"00000000",
          proto_any => false, proto => PROTO_TCP,
          dport_lo => 22, dport_hi => 22,
          drop => false),
    -- 3: drop SSH from anywhere else
    3 => (enabled => true,
          src_ip => x"00000000", src_mask => x"00000000",
          dst_ip => x"00000000", dst_mask => x"00000000",
          proto_any => false, proto => PROTO_TCP,
          dport_lo => 22, dport_hi => 22,
          drop => true),
    -- 4: drop UDP to high ports of the web server 192.168.1.100
    4 => (enabled => true,
          src_ip => x"00000000", src_mask => x"00000000",
          dst_ip => x"C0A80164", dst_mask => x"FFFFFFFF",
          proto_any => false, proto => PROTO_UDP,
          dport_lo => 1024, dport_hi => 65535,
          drop => true),
    others => UNUSED_RULE);

end package filter_rules_pkg;