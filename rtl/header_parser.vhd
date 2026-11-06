-- Streaming header parser for Ethernet II / IPv4 / UDP-TCP packets.
--
-- Bytes arrive one at a time on in_data when in_valid = '1'.
-- in_last = '1' marks the last byte of a packet.
-- The parser counts bytes and copies the interesting ones into output
-- registers. When byte 37 has been received, hdr_valid is high for one
-- clock cycle and all output fields are ready.
--
-- Byte positions (Ethernet II without VLAN, IPv4 header of 20 bytes):
--   12-13 EtherType      23 IP protocol
--   26-29 IP source      30-33 IP destination
--   34-35 source port    36-37 destination port (UDP and TCP)
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity header_parser is
  port (
    clk           : in  std_logic;
    rst           : in  std_logic;                      -- synchronous, active high
    -- input byte stream
    in_valid      : in  std_logic;
    in_data       : in  std_logic_vector(7 downto 0);
    in_last       : in  std_logic;
    -- extracted fields
    ethertype     : out std_logic_vector(15 downto 0);
    ip_proto      : out std_logic_vector(7 downto 0);
    ip_src        : out std_logic_vector(31 downto 0);
    ip_dst        : out std_logic_vector(31 downto 0);
    port_src      : out std_logic_vector(15 downto 0);
    port_dst      : out std_logic_vector(15 downto 0);
    hdr_valid     : out std_logic;                      -- one-cycle pulse
    hdr_supported : out std_logic                       -- '1' = IPv4 with 20-byte header
  );
end entity header_parser;

architecture rtl of header_parser is
  constant LAST_HDR_BYTE : natural := 37;

  type state_t is (S_HEADER, S_PAYLOAD);
  signal state : state_t := S_HEADER;

  signal byte_cnt : unsigned(5 downto 0) := (others => '0');  -- 0 to 63

  -- internal copies of the outputs
  signal r_ethertype   : std_logic_vector(15 downto 0) := (others => '0');
  signal r_version_ihl : std_logic_vector(7 downto 0)  := (others => '0');
  signal r_ip_proto    : std_logic_vector(7 downto 0)  := (others => '0');
  signal r_ip_src      : std_logic_vector(31 downto 0) := (others => '0');
  signal r_ip_dst      : std_logic_vector(31 downto 0) := (others => '0');
  signal r_port_src    : std_logic_vector(15 downto 0) := (others => '0');
  signal r_port_dst    : std_logic_vector(15 downto 0) := (others => '0');
  signal r_hdr_valid   : std_logic := '0';
  signal r_supported   : std_logic := '0';
begin

  process (clk)
  begin
    if rising_edge(clk) then
      r_hdr_valid <= '0';                       -- default: no pulse

      if rst = '1' then
        state       <= S_HEADER;
        byte_cnt    <= (others => '0');
        r_supported <= '0';

      elsif in_valid = '1' then

        if state = S_HEADER then
          -- 1. copy the byte into the right field
          case to_integer(byte_cnt) is
            when 12 => r_ethertype(15 downto 8) <= in_data;
            when 13 => r_ethertype(7 downto 0)  <= in_data;
            when 14 => r_version_ihl            <= in_data;
            when 23 => r_ip_proto               <= in_data;
            when 26 => r_ip_src(31 downto 24)   <= in_data;
            when 27 => r_ip_src(23 downto 16)   <= in_data;
            when 28 => r_ip_src(15 downto 8)    <= in_data;
            when 29 => r_ip_src(7 downto 0)     <= in_data;
            when 30 => r_ip_dst(31 downto 24)   <= in_data;
            when 31 => r_ip_dst(23 downto 16)   <= in_data;
            when 32 => r_ip_dst(15 downto 8)    <= in_data;
            when 33 => r_ip_dst(7 downto 0)     <= in_data;
            when 34 => r_port_src(15 downto 8)  <= in_data;
            when 35 => r_port_src(7 downto 0)   <= in_data;
            when 36 => r_port_dst(15 downto 8)  <= in_data;
            when 37 => r_port_dst(7 downto 0)   <= in_data;
            when others => null;                -- byte not needed
          end case;

          -- 2. move forward
          if byte_cnt = LAST_HDR_BYTE then
            r_hdr_valid <= '1';                 -- all fields are ready next cycle
            if r_ethertype = x"0800" and r_version_ihl = x"45" then
              r_supported <= '1';
            else
              r_supported <= '0';
            end if;
            state <= S_PAYLOAD;
          else
            byte_cnt <= byte_cnt + 1;
          end if;
        end if;

        -- 3. end of packet: get ready for the next one
        if in_last = '1' then
          state    <= S_HEADER;
          byte_cnt <= (others => '0');
        end if;

      end if;
    end if;
  end process;

  ethertype     <= r_ethertype;
  ip_proto      <= r_ip_proto;
  ip_src        <= r_ip_src;
  ip_dst        <= r_ip_dst;
  port_src      <= r_port_src;
  port_dst      <= r_port_dst;
  hdr_valid     <= r_hdr_valid;
  hdr_supported <= r_supported;

end architecture rtl;