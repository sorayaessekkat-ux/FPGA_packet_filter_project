-- Packet filter: header parser + rule engine + statistics counters.
--
--   byte stream --> header_parser --> rule_engine --> decision
--                                                \--> counters
--
-- The decision for a packet comes out 2 clock cycles after its last
-- header byte (byte 37), whatever the packet: the latency is fixed.
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity packet_filter is
  port (
    clk            : in  std_logic;
    rst            : in  std_logic;
    -- input byte stream
    in_valid       : in  std_logic;
    in_data        : in  std_logic_vector(7 downto 0);
    in_last        : in  std_logic;
    -- decision for each packet
    decision_valid : out std_logic;
    decision_drop  : out std_logic;
    rule_hit       : out std_logic;
    rule_index     : out std_logic_vector(2 downto 0);
    -- statistics
    cnt_accepted   : out std_logic_vector(31 downto 0);
    cnt_dropped    : out std_logic_vector(31 downto 0)
  );
end entity packet_filter;

architecture rtl of packet_filter is
  -- wires between the parser and the rule engine
  signal hdr_valid     : std_logic;
  signal hdr_supported : std_logic;
  signal ip_proto      : std_logic_vector(7 downto 0);
  signal ip_src        : std_logic_vector(31 downto 0);
  signal ip_dst        : std_logic_vector(31 downto 0);
  signal port_dst      : std_logic_vector(15 downto 0);

  signal dec_valid : std_logic;
  signal dec_drop  : std_logic;

  signal accepted : unsigned(31 downto 0) := (others => '0');
  signal dropped  : unsigned(31 downto 0) := (others => '0');
begin

  parser : entity work.header_parser
    port map (
      clk           => clk,
      rst           => rst,
      in_valid      => in_valid,
      in_data       => in_data,
      in_last       => in_last,
      ethertype     => open,
      ip_proto      => ip_proto,
      ip_src        => ip_src,
      ip_dst        => ip_dst,
      port_src      => open,
      port_dst      => port_dst,
      hdr_valid     => hdr_valid,
      hdr_supported => hdr_supported);

  rules : entity work.rule_engine
    port map (
      clk            => clk,
      rst            => rst,
      hdr_valid      => hdr_valid,
      hdr_supported  => hdr_supported,
      ip_proto       => ip_proto,
      ip_src         => ip_src,
      ip_dst         => ip_dst,
      port_dst       => port_dst,
      decision_valid => dec_valid,
      decision_drop  => dec_drop,
      rule_hit       => rule_hit,
      rule_index     => rule_index);

  -- statistics: count accepted and dropped packets
  process (clk)
  begin
    if rising_edge(clk) then
      if rst = '1' then
        accepted <= (others => '0');
        dropped  <= (others => '0');
      elsif dec_valid = '1' then
        if dec_drop = '1' then
          dropped <= dropped + 1;
        else
          accepted <= accepted + 1;
        end if;
      end if;
    end if;
  end process;

  decision_valid <= dec_valid;
  decision_drop  <= dec_drop;
  cnt_accepted   <= std_logic_vector(accepted);
  cnt_dropped    <= std_logic_vector(dropped);

end architecture rtl;