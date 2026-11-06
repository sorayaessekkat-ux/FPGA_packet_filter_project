-- Rule engine: compares the parsed header with every rule in parallel.
--
-- One clock cycle after hdr_valid, decision_valid is high for one cycle
-- and tells whether the packet must be dropped and which rule matched.
-- Packets that are not IPv4 (hdr_supported = '0') are not checked
-- against the rules: they get the default action.
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.filter_rules_pkg.all;

entity rule_engine is
  port (
    clk            : in  std_logic;
    rst            : in  std_logic;
    -- header fields from the parser
    hdr_valid      : in  std_logic;
    hdr_supported  : in  std_logic;
    ip_proto       : in  std_logic_vector(7 downto 0);
    ip_src         : in  std_logic_vector(31 downto 0);
    ip_dst         : in  std_logic_vector(31 downto 0);
    port_dst       : in  std_logic_vector(15 downto 0);
    -- decision
    decision_valid : out std_logic;                     -- one-cycle pulse
    decision_drop  : out std_logic;                     -- '1' = drop
    rule_hit       : out std_logic;                     -- '1' = a rule matched
    rule_index     : out std_logic_vector(2 downto 0)   -- which rule matched
  );
end entity rule_engine;

architecture rtl of rule_engine is

  -- Does one rule match the header?
  function rule_matches (r     : rule_t;
                         src   : std_logic_vector(31 downto 0);
                         dst   : std_logic_vector(31 downto 0);
                         proto : std_logic_vector(7 downto 0);
                         dport : std_logic_vector(15 downto 0)) return boolean is
    variable p : natural;
  begin
    p := to_integer(unsigned(dport));
    return r.enabled
       and (src and r.src_mask) = (r.src_ip and r.src_mask)
       and (dst and r.dst_mask) = (r.dst_ip and r.dst_mask)
       and (r.proto_any or proto = r.proto)
       and p >= r.dport_lo and p <= r.dport_hi;
  end function;

  signal r_valid : std_logic := '0';
  signal r_drop  : std_logic := '0';
  signal r_hit   : std_logic := '0';
  signal r_index : unsigned(2 downto 0) := (others => '0');

begin

  process (clk)
    variable hit   : boolean;
    variable drop  : boolean;
    variable index : natural range 0 to NUM_RULES - 1;
  begin
    if rising_edge(clk) then
      r_valid <= '0';                                -- default: no pulse

      if rst = '1' then
        r_drop  <= '0';
        r_hit   <= '0';
        r_index <= (others => '0');

      elsif hdr_valid = '1' then
        hit   := false;
        drop  := DEFAULT_DROP;
        index := 0;

        if hdr_supported = '1' then
          -- All rules are compared at the same time (8 comparators in
          -- hardware). Going from the last rule to the first one makes
          -- the lowest matching index win.
          for i in NUM_RULES - 1 downto 0 loop
            if rule_matches(RULES(i), ip_src, ip_dst, ip_proto, port_dst) then
              hit   := true;
              drop  := RULES(i).drop;
              index := i;
            end if;
          end loop;
        end if;

        r_valid <= '1';
        if hit then
          r_hit <= '1';
        else
          r_hit <= '0';
        end if;
        if drop then
          r_drop <= '1';
        else
          r_drop <= '0';
        end if;
        r_index <= to_unsigned(index, 3);
      end if;
    end if;
  end process;

  decision_valid <= r_valid;
  decision_drop  <= r_drop;
  rule_hit       <= r_hit;
  rule_index     <= std_logic_vector(r_index);

end architecture rtl;