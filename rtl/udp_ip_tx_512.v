/*

Copyright (c) 2014-2018 Alex Forencich

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*/

/*
* Modified by Gabriele Bortolato gabriele.bortolato@cern.ch
* Need to support RoCEv2 UDP packets, udp_length is increased by 4 to accomodate the ICRC value.
* The actual value is inserted later after the IP stack (ICRC is computed on UDP and IP headers as well).
* */


// Language: Verilog 2001

`resetall `timescale 1ns / 1ps `default_nettype none

/*
 * UDP ethernet frame transmitter (UDP frame in, IP frame out,512 bit datapath)
 */
module udp_ip_tx_512 (
    input wire clk,
    input wire rst,

    /*
     * UDP frame input
     */
    input  wire         s_udp_hdr_valid,
    output wire         s_udp_hdr_ready,
    input  wire [ 47:0] s_eth_dest_mac,
    input  wire [ 47:0] s_eth_src_mac,
    input  wire [ 15:0] s_eth_type,
    input  wire [  3:0] s_ip_version,
    input  wire [  3:0] s_ip_ihl,
    input  wire [  5:0] s_ip_dscp,
    input  wire [  1:0] s_ip_ecn,
    input  wire [ 15:0] s_ip_identification,
    input  wire [  2:0] s_ip_flags,
    input  wire [ 12:0] s_ip_fragment_offset,
    input  wire [  7:0] s_ip_ttl,
    input  wire [  7:0] s_ip_protocol,
    input  wire [ 15:0] s_ip_header_checksum,
    input  wire [ 31:0] s_ip_source_ip,
    input  wire [ 31:0] s_ip_dest_ip,
    input  wire [ 15:0] s_udp_source_port,
    input  wire [ 15:0] s_udp_dest_port,
    input  wire [ 15:0] s_udp_length,
    input  wire [ 15:0] s_udp_checksum,
    input  wire [511:0] s_udp_payload_axis_tdata,
    input  wire [ 63:0] s_udp_payload_axis_tkeep,
    input  wire         s_udp_payload_axis_tvalid,
    output wire         s_udp_payload_axis_tready,
    input  wire         s_udp_payload_axis_tlast,
    input  wire         s_udp_payload_axis_tuser,

    /*
     * IP frame output
     */
    output wire         m_ip_hdr_valid,
    input  wire         m_ip_hdr_ready,
    output wire [ 47:0] m_eth_dest_mac,
    output wire [ 47:0] m_eth_src_mac,
    output wire [ 15:0] m_eth_type,
    output wire [  3:0] m_ip_version,
    output wire [  3:0] m_ip_ihl,
    output wire [  5:0] m_ip_dscp,
    output wire [  1:0] m_ip_ecn,
    output wire [ 15:0] m_ip_length,
    output wire [ 15:0] m_ip_identification,
    output wire [  2:0] m_ip_flags,
    output wire [ 12:0] m_ip_fragment_offset,
    output wire [  7:0] m_ip_ttl,
    output wire [  7:0] m_ip_protocol,
    output wire [ 15:0] m_ip_header_checksum,
    output wire [ 31:0] m_ip_source_ip,
    output wire [ 31:0] m_ip_dest_ip,
    output wire         m_is_roce_packet,
    output wire [511:0] m_ip_payload_axis_tdata,
    output wire [ 63:0] m_ip_payload_axis_tkeep,
    output wire         m_ip_payload_axis_tvalid,
    input  wire         m_ip_payload_axis_tready,
    output wire         m_ip_payload_axis_tlast,
    output wire         m_ip_payload_axis_tuser,

    /*
     * Status signals
     */
    output wire busy,
    output wire error_payload_early_termination
);

  /*

UDP Frame

 Field                       Length
 Destination MAC address     6 octets
 Source MAC address          6 octets
 Ethertype (0x0800)          2 octets
 Version (4)                 4 bits
 IHL (5-15)                  4 bits
 DSCP (0)                    6 bits
 ECN (0)                     2 bits
 length                      2 octets
 identification (0?)         2 octets
 flags (010)                 3 bits
 fragment offset (0)         13 bits
 time to live (64?)          1 octet
 protocol                    1 octet
 header checksum             2 octets
 source IP                   4 octets
 destination IP              4 octets
 options                     (IHL-5)*4 octets

 source port                 2 octets
 desination port             2 octets
 length                      2 octets
 checksum                    2 octets

 payload                     length octets

This module receives a UDP frame with header fields in parallel along with the
payload in an AXI stream, combines the header with the payload, passes through
the IP headers, and transmits the complete IP payload on an AXI interface.

*/

  localparam [15:0] ROCE_UDP_PORT = 16'h12B7;

  localparam [2:0]
    STATE_IDLE = 3'd0,
    STATE_WRITE_HEADER = 3'd1,
    STATE_WRITE_PAYLOAD = 3'd2,
    STATE_WRITE_PAYLOAD_LAST = 3'd3,
    STATE_WAIT_LAST = 3'd4;

  reg [2:0] state_reg = STATE_IDLE, state_next;

  // datapath control signals
  reg store_udp_hdr;
  reg store_last_word;

  reg flush_save;
  reg transfer_in_save;

  reg [15:0] word_count_reg = 16'd0, word_count_next;

  reg [511:0] last_word_data_reg = 512'd0;
  reg [ 63:0] last_word_keep_reg = 64'd0;

  reg [ 15:0] udp_source_port_reg = 16'd0;
  reg [ 15:0] udp_dest_port_reg = 16'd0;
  reg [ 15:0] udp_length_reg = 16'd0;
  reg [ 15:0] udp_checksum_reg = 16'd0;

  reg s_udp_hdr_ready_reg = 1'b0, s_udp_hdr_ready_next;
  reg s_udp_payload_axis_tready_reg = 1'b0, s_udp_payload_axis_tready_next;

  reg m_ip_hdr_valid_reg = 1'b0, m_ip_hdr_valid_next;
  reg [47:0] m_eth_dest_mac_reg = 48'd0;
  reg [47:0] m_eth_src_mac_reg = 48'd0;
  reg [15:0] m_eth_type_reg = 16'd0;
  reg [3:0] m_ip_version_reg = 4'd0;
  reg [3:0] m_ip_ihl_reg = 4'd0;
  reg [5:0] m_ip_dscp_reg = 6'd0;
  reg [1:0] m_ip_ecn_reg = 2'd0;
  reg [15:0] m_ip_length_reg = 16'd0;
  reg [15:0] m_ip_identification_reg = 16'd0;
  reg [2:0] m_ip_flags_reg = 3'd0;
  reg [12:0] m_ip_fragment_offset_reg = 13'd0;
  reg [7:0] m_ip_ttl_reg = 8'd0;
  reg [7:0] m_ip_protocol_reg = 8'd0;
  reg [15:0] m_ip_header_checksum_reg = 16'd0;
  reg [31:0] m_ip_source_ip_reg = 32'd0;
  reg [31:0] m_ip_dest_ip_reg = 32'd0;
  reg m_is_roce_packet_reg = 32'd0;

  reg busy_reg = 1'b0;
  reg error_payload_early_termination_reg = 1'b0, error_payload_early_termination_next;

  reg  [511:0] save_udp_payload_axis_tdata_reg = 512'd0;
  reg  [ 63:0] save_udp_payload_axis_tkeep_reg = 64'd0;
  reg          save_udp_payload_axis_tlast_reg = 1'b0;
  reg          save_udp_payload_axis_tuser_reg = 1'b0;

  reg  [511:0] shift_udp_payload_axis_tdata;
  reg  [ 63:0] shift_udp_payload_axis_tkeep;
  reg          shift_udp_payload_axis_tvalid;
  reg          shift_udp_payload_axis_tlast;
  reg          shift_udp_payload_axis_tuser;
  reg          shift_udp_payload_s_tready;
  reg          shift_udp_payload_extra_cycle_reg = 1'b0;

  // internal datapath
  reg  [511:0] m_ip_payload_axis_tdata_int;
  reg  [ 63:0] m_ip_payload_axis_tkeep_int;
  reg          m_ip_payload_axis_tvalid_int;
  reg          m_ip_payload_axis_tready_int_reg = 1'b0;
  reg          m_ip_payload_axis_tlast_int;
  reg          m_ip_payload_axis_tuser_int;
  wire         m_ip_payload_axis_tready_int_early;

  wire [ 15:0] udp_length_roce_int;
  reg  [ 15:0] udp_length_roce_reg;

  assign udp_length_roce_int             = s_udp_length + 16'd4;

  assign s_udp_hdr_ready                 = s_udp_hdr_ready_reg;
  assign s_udp_payload_axis_tready       = s_udp_payload_axis_tready_reg;

  assign m_ip_hdr_valid                  = m_ip_hdr_valid_reg;
  assign m_eth_dest_mac                  = m_eth_dest_mac_reg;
  assign m_eth_src_mac                   = m_eth_src_mac_reg;
  assign m_eth_type                      = m_eth_type_reg;
  assign m_ip_version                    = m_ip_version_reg;
  assign m_ip_ihl                        = m_ip_ihl_reg;
  assign m_ip_dscp                       = m_ip_dscp_reg;
  assign m_ip_ecn                        = m_ip_ecn_reg;
  assign m_ip_length                     = m_ip_length_reg;
  assign m_ip_identification             = m_ip_identification_reg;
  assign m_ip_flags                      = m_ip_flags_reg;
  assign m_ip_fragment_offset            = m_ip_fragment_offset_reg;
  assign m_ip_ttl                        = m_ip_ttl_reg;
  assign m_ip_protocol                   = m_ip_protocol_reg;
  assign m_ip_header_checksum            = m_ip_header_checksum_reg;
  assign m_ip_source_ip                  = m_ip_source_ip_reg;
  assign m_ip_dest_ip                    = m_ip_dest_ip_reg;
  assign m_is_roce_packet                = m_is_roce_packet_reg;

  assign busy                            = busy_reg;
  assign error_payload_early_termination = error_payload_early_termination_reg;

  function [15:0] keep2count;
    input [63:0] k;
    casez (k)
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz0: keep2count = 16'd0;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz01: keep2count = 16'd1;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz011: keep2count = 16'd2;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz0111: keep2count = 16'd3;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz01111: keep2count = 16'd4;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz011111: keep2count = 16'd5;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz0111111: keep2count = 16'd6;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz01111111: keep2count = 16'd7;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz011111111: keep2count = 16'd8;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz0111111111: keep2count = 16'd9;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz01111111111: keep2count = 16'd10;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz011111111111: keep2count = 16'd11;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz0111111111111: keep2count = 16'd12;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz01111111111111: keep2count = 16'd13;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz011111111111111: keep2count = 16'd14;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz0111111111111111: keep2count = 16'd15;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz01111111111111111: keep2count = 16'd16;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz011111111111111111: keep2count = 16'd17;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz0111111111111111111: keep2count = 16'd18;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz01111111111111111111: keep2count = 16'd19;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz011111111111111111111: keep2count = 16'd20;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz0111111111111111111111: keep2count = 16'd21;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz01111111111111111111111: keep2count = 16'd22;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz011111111111111111111111: keep2count = 16'd23;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz0111111111111111111111111: keep2count = 16'd24;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz01111111111111111111111111: keep2count = 16'd25;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz011111111111111111111111111: keep2count = 16'd26;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz0111111111111111111111111111: keep2count = 16'd27;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz01111111111111111111111111111: keep2count = 16'd28;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz011111111111111111111111111111: keep2count = 16'd29;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz0111111111111111111111111111111: keep2count = 16'd30;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz01111111111111111111111111111111: keep2count = 16'd31;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz011111111111111111111111111111111: keep2count = 16'd32;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz0111111111111111111111111111111111: keep2count = 16'd33;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzzz01111111111111111111111111111111111: keep2count = 16'd34;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzzz011111111111111111111111111111111111: keep2count = 16'd35;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzzz0111111111111111111111111111111111111: keep2count = 16'd36;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzzz01111111111111111111111111111111111111: keep2count = 16'd37;
      64'bzzzzzzzzzzzzzzzzzzzzzzzzz011111111111111111111111111111111111111: keep2count = 16'd38;
      64'bzzzzzzzzzzzzzzzzzzzzzzzz0111111111111111111111111111111111111111: keep2count = 16'd39;
      64'bzzzzzzzzzzzzzzzzzzzzzzz01111111111111111111111111111111111111111: keep2count = 16'd40;
      64'bzzzzzzzzzzzzzzzzzzzzzz011111111111111111111111111111111111111111: keep2count = 16'd41;
      64'bzzzzzzzzzzzzzzzzzzzzz0111111111111111111111111111111111111111111: keep2count = 16'd42;
      64'bzzzzzzzzzzzzzzzzzzzz01111111111111111111111111111111111111111111: keep2count = 16'd43;
      64'bzzzzzzzzzzzzzzzzzzz011111111111111111111111111111111111111111111: keep2count = 16'd44;
      64'bzzzzzzzzzzzzzzzzzz0111111111111111111111111111111111111111111111: keep2count = 16'd45;
      64'bzzzzzzzzzzzzzzzzz01111111111111111111111111111111111111111111111: keep2count = 16'd46;
      64'bzzzzzzzzzzzzzzzz011111111111111111111111111111111111111111111111: keep2count = 16'd47;
      64'bzzzzzzzzzzzzzzz0111111111111111111111111111111111111111111111111: keep2count = 16'd48;
      64'bzzzzzzzzzzzzzz01111111111111111111111111111111111111111111111111: keep2count = 16'd49;
      64'bzzzzzzzzzzzzz011111111111111111111111111111111111111111111111111: keep2count = 16'd50;
      64'bzzzzzzzzzzzz0111111111111111111111111111111111111111111111111111: keep2count = 16'd51;
      64'bzzzzzzzzzzz01111111111111111111111111111111111111111111111111111: keep2count = 16'd52;
      64'bzzzzzzzzzz011111111111111111111111111111111111111111111111111111: keep2count = 16'd53;
      64'bzzzzzzzzz0111111111111111111111111111111111111111111111111111111: keep2count = 16'd54;
      64'bzzzzzzzz01111111111111111111111111111111111111111111111111111111: keep2count = 16'd55;
      64'bzzzzzzz011111111111111111111111111111111111111111111111111111111: keep2count = 16'd56;
      64'bzzzzzz0111111111111111111111111111111111111111111111111111111111: keep2count = 16'd57;
      64'bzzzzz01111111111111111111111111111111111111111111111111111111111: keep2count = 16'd58;
      64'bzzzz011111111111111111111111111111111111111111111111111111111111: keep2count = 16'd59;
      64'bzzz0111111111111111111111111111111111111111111111111111111111111: keep2count = 16'd60;
      64'bzz01111111111111111111111111111111111111111111111111111111111111: keep2count = 16'd61;
      64'bz011111111111111111111111111111111111111111111111111111111111111: keep2count = 16'd62;
      64'b0111111111111111111111111111111111111111111111111111111111111111: keep2count = 16'd63;
      64'b1111111111111111111111111111111111111111111111111111111111111111: keep2count = 16'd64;
    endcase
  endfunction

  function [63:0] count2keep;
    input [6:0] k;
    case (k)
      7'd0:    count2keep = 64'b0000000000000000000000000000000000000000000000000000000000000000;
      7'd1:    count2keep = 64'b0000000000000000000000000000000000000000000000000000000000000001;
      7'd2:    count2keep = 64'b0000000000000000000000000000000000000000000000000000000000000011;
      7'd3:    count2keep = 64'b0000000000000000000000000000000000000000000000000000000000000111;
      7'd4:    count2keep = 64'b0000000000000000000000000000000000000000000000000000000000001111;
      7'd5:    count2keep = 64'b0000000000000000000000000000000000000000000000000000000000011111;
      7'd6:    count2keep = 64'b0000000000000000000000000000000000000000000000000000000000111111;
      7'd7:    count2keep = 64'b0000000000000000000000000000000000000000000000000000000001111111;
      7'd8:    count2keep = 64'b0000000000000000000000000000000000000000000000000000000011111111;
      7'd9:    count2keep = 64'b0000000000000000000000000000000000000000000000000000000111111111;
      7'd10:   count2keep = 64'b0000000000000000000000000000000000000000000000000000001111111111;
      7'd11:   count2keep = 64'b0000000000000000000000000000000000000000000000000000011111111111;
      7'd12:   count2keep = 64'b0000000000000000000000000000000000000000000000000000111111111111;
      7'd13:   count2keep = 64'b0000000000000000000000000000000000000000000000000001111111111111;
      7'd14:   count2keep = 64'b0000000000000000000000000000000000000000000000000011111111111111;
      7'd15:   count2keep = 64'b0000000000000000000000000000000000000000000000000111111111111111;
      7'd16:   count2keep = 64'b0000000000000000000000000000000000000000000000001111111111111111;
      7'd17:   count2keep = 64'b0000000000000000000000000000000000000000000000011111111111111111;
      7'd18:   count2keep = 64'b0000000000000000000000000000000000000000000000111111111111111111;
      7'd19:   count2keep = 64'b0000000000000000000000000000000000000000000001111111111111111111;
      7'd20:   count2keep = 64'b0000000000000000000000000000000000000000000011111111111111111111;
      7'd21:   count2keep = 64'b0000000000000000000000000000000000000000000111111111111111111111;
      7'd22:   count2keep = 64'b0000000000000000000000000000000000000000001111111111111111111111;
      7'd23:   count2keep = 64'b0000000000000000000000000000000000000000011111111111111111111111;
      7'd24:   count2keep = 64'b0000000000000000000000000000000000000000111111111111111111111111;
      7'd25:   count2keep = 64'b0000000000000000000000000000000000000001111111111111111111111111;
      7'd26:   count2keep = 64'b0000000000000000000000000000000000000011111111111111111111111111;
      7'd27:   count2keep = 64'b0000000000000000000000000000000000000111111111111111111111111111;
      7'd28:   count2keep = 64'b0000000000000000000000000000000000001111111111111111111111111111;
      7'd29:   count2keep = 64'b0000000000000000000000000000000000011111111111111111111111111111;
      7'd30:   count2keep = 64'b0000000000000000000000000000000000111111111111111111111111111111;
      7'd31:   count2keep = 64'b0000000000000000000000000000000001111111111111111111111111111111;
      7'd32:   count2keep = 64'b0000000000000000000000000000000011111111111111111111111111111111;
      7'd33:   count2keep = 64'b0000000000000000000000000000000111111111111111111111111111111111;
      7'd34:   count2keep = 64'b0000000000000000000000000000001111111111111111111111111111111111;
      7'd35:   count2keep = 64'b0000000000000000000000000000011111111111111111111111111111111111;
      7'd36:   count2keep = 64'b0000000000000000000000000000111111111111111111111111111111111111;
      7'd37:   count2keep = 64'b0000000000000000000000000001111111111111111111111111111111111111;
      7'd38:   count2keep = 64'b0000000000000000000000000011111111111111111111111111111111111111;
      7'd39:   count2keep = 64'b0000000000000000000000000111111111111111111111111111111111111111;
      7'd40:   count2keep = 64'b0000000000000000000000001111111111111111111111111111111111111111;
      7'd41:   count2keep = 64'b0000000000000000000000011111111111111111111111111111111111111111;
      7'd42:   count2keep = 64'b0000000000000000000000111111111111111111111111111111111111111111;
      7'd43:   count2keep = 64'b0000000000000000000001111111111111111111111111111111111111111111;
      7'd44:   count2keep = 64'b0000000000000000000011111111111111111111111111111111111111111111;
      7'd45:   count2keep = 64'b0000000000000000000111111111111111111111111111111111111111111111;
      7'd46:   count2keep = 64'b0000000000000000001111111111111111111111111111111111111111111111;
      7'd47:   count2keep = 64'b0000000000000000011111111111111111111111111111111111111111111111;
      7'd48:   count2keep = 64'b0000000000000000111111111111111111111111111111111111111111111111;
      7'd49:   count2keep = 64'b0000000000000001111111111111111111111111111111111111111111111111;
      7'd50:   count2keep = 64'b0000000000000011111111111111111111111111111111111111111111111111;
      7'd51:   count2keep = 64'b0000000000000111111111111111111111111111111111111111111111111111;
      7'd52:   count2keep = 64'b0000000000001111111111111111111111111111111111111111111111111111;
      7'd53:   count2keep = 64'b0000000000011111111111111111111111111111111111111111111111111111;
      7'd54:   count2keep = 64'b0000000000111111111111111111111111111111111111111111111111111111;
      7'd55:   count2keep = 64'b0000000001111111111111111111111111111111111111111111111111111111;
      7'd56:   count2keep = 64'b0000000011111111111111111111111111111111111111111111111111111111;
      7'd57:   count2keep = 64'b0000000111111111111111111111111111111111111111111111111111111111;
      7'd58:   count2keep = 64'b0000001111111111111111111111111111111111111111111111111111111111;
      7'd59:   count2keep = 64'b0000011111111111111111111111111111111111111111111111111111111111;
      7'd60:   count2keep = 64'b0000111111111111111111111111111111111111111111111111111111111111;
      7'd61:   count2keep = 64'b0001111111111111111111111111111111111111111111111111111111111111;
      7'd62:   count2keep = 64'b0011111111111111111111111111111111111111111111111111111111111111;
      7'd63:   count2keep = 64'b0111111111111111111111111111111111111111111111111111111111111111;
      7'd64:   count2keep = 64'b1111111111111111111111111111111111111111111111111111111111111111;
      default: count2keep = 64'b1111111111111111111111111111111111111111111111111111111111111111;
    endcase
  endfunction

  always @* begin
    shift_udp_payload_axis_tdata[63:0] = save_udp_payload_axis_tdata_reg[511:448];
    shift_udp_payload_axis_tkeep[7:0]  = save_udp_payload_axis_tkeep_reg[63:56];

    if (shift_udp_payload_extra_cycle_reg) begin
      shift_udp_payload_axis_tdata[511:64] = 448'd0;
      shift_udp_payload_axis_tkeep[63:8] = 52'd0;
      shift_udp_payload_axis_tvalid = 1'b1;
      shift_udp_payload_axis_tlast = save_udp_payload_axis_tlast_reg;
      shift_udp_payload_axis_tuser = save_udp_payload_axis_tuser_reg;
      shift_udp_payload_s_tready = flush_save;
    end else begin
      shift_udp_payload_axis_tdata[511:64] = s_udp_payload_axis_tdata[447:0];
      shift_udp_payload_axis_tkeep[63:8] = s_udp_payload_axis_tkeep[55:0];
      shift_udp_payload_axis_tvalid = s_udp_payload_axis_tvalid;
      shift_udp_payload_axis_tlast = (s_udp_payload_axis_tlast && (s_udp_payload_axis_tkeep[63:56] == 0));
      shift_udp_payload_axis_tuser = (s_udp_payload_axis_tuser && (s_udp_payload_axis_tkeep[63:56] == 0));
      shift_udp_payload_s_tready = !(s_udp_payload_axis_tlast && s_udp_payload_axis_tvalid && transfer_in_save) & !save_udp_payload_axis_tlast_reg;
    end
  end

  always @* begin
    state_next = STATE_IDLE;

    s_udp_hdr_ready_next = 1'b0;
    s_udp_payload_axis_tready_next = 1'b0;

    store_udp_hdr = 1'b0;

    store_last_word = 1'b0;

    flush_save = 1'b0;
    transfer_in_save = 1'b0;

    word_count_next = word_count_reg;


    m_ip_hdr_valid_next = m_ip_hdr_valid_reg && !m_ip_hdr_ready;

    error_payload_early_termination_next = 1'b0;

    m_ip_payload_axis_tdata_int = 1'b0;
    m_ip_payload_axis_tkeep_int = 1'b0;
    m_ip_payload_axis_tvalid_int = 1'b0;
    m_ip_payload_axis_tlast_int = 1'b0;
    m_ip_payload_axis_tuser_int = 1'b0;

    case (state_reg)
      STATE_IDLE: begin
        // idle state - wait for data
        flush_save = 1'b1;
        s_udp_hdr_ready_next = !m_ip_hdr_valid_next;

        if (s_udp_hdr_ready && s_udp_hdr_valid) begin
          store_udp_hdr = 1'b1;


          s_udp_hdr_ready_next = 1'b0;
          m_ip_hdr_valid_next = 1'b1;
          //s_udp_payload_axis_tready_next = m_ip_payload_axis_tready_int_early;
          /*
          if (m_ip_payload_axis_tready_int_reg && shift_udp_payload_axis_tvalid) begin
            transfer_in_save = 1'b1;
            m_ip_payload_axis_tvalid_int = 1'b1;
            m_ip_payload_axis_tdata_int[7:0] = s_udp_source_port[15:8];
            m_ip_payload_axis_tdata_int[15:8] = s_udp_source_port[7:0];
            m_ip_payload_axis_tdata_int[23:16] = s_udp_dest_port[15:8];
            m_ip_payload_axis_tdata_int[31:24] = s_udp_dest_port[7:0];
            if (s_udp_dest_port == ROCE_UDP_PORT) begin
              m_ip_payload_axis_tdata_int[39:32] = udp_length_roce_int[15:8];
              m_ip_payload_axis_tdata_int[47:40] = udp_length_roce_int[7:0];
            end else begin
              m_ip_payload_axis_tdata_int[39:32] = s_udp_length[15:8];
              m_ip_payload_axis_tdata_int[47:40] = s_udp_length[7:0];
            end
            m_ip_payload_axis_tdata_int[55:48] = s_udp_checksum[15:8];
            m_ip_payload_axis_tdata_int[63:56] = s_udp_checksum[7:0];
            m_ip_payload_axis_tdata_int[511:64] = shift_udp_payload_axis_tdata[511:64];
            m_ip_payload_axis_tkeep_int = {shift_udp_payload_axis_tkeep[63:8], 8'hFF};
            //s_udp_payload_axis_tready_next = m_ip_payload_axis_tready_int_early;

            word_count_next = s_udp_length - keep2count(m_ip_payload_axis_tkeep_int);

            s_udp_payload_axis_tready_next = m_ip_payload_axis_tready_int_early && shift_udp_payload_s_tready;
            if (s_udp_length - keep2count(m_ip_payload_axis_tkeep_int) == 16'd0) begin
              // have entire payload 
              if (shift_udp_payload_axis_tlast) begin
                m_ip_payload_axis_tlast_int = 1'b1;
                s_udp_hdr_ready_next = !m_ip_hdr_valid_next;
                s_udp_payload_axis_tready_next = 1'b0;
                state_next = STATE_IDLE;
              end else begin
                store_last_word = 1'b1;
                s_udp_payload_axis_tready_next = shift_udp_payload_s_tready;
                m_ip_payload_axis_tvalid_int = 1'b0;
                state_next = STATE_WRITE_PAYLOAD_LAST;
              end
            end else begin
              if (shift_udp_payload_axis_tlast) begin
                // end of frame, but length does not match
                error_payload_early_termination_next = 1'b1;
                s_udp_payload_axis_tready_next = shift_udp_payload_s_tready;
                m_ip_payload_axis_tuser_int = 1'b1;
                state_next = STATE_WAIT_LAST;
              end else begin
                //s_udp_payload_axis_tready_next = m_ip_payload_axis_tready_int_early && shift_udp_payload_s_tready;
                state_next = STATE_WRITE_PAYLOAD;
              end
            end
          end else begin
            state_next = STATE_WRITE_HEADER;
        end
        */
          state_next = STATE_WRITE_HEADER;
        end else begin
          state_next = STATE_IDLE;
        end
      end
      STATE_WRITE_HEADER: begin
        // write header
        s_udp_payload_axis_tready_next = m_ip_payload_axis_tready_int_early && shift_udp_payload_s_tready;

        if (s_udp_payload_axis_tready && s_udp_payload_axis_tvalid) begin
          transfer_in_save = 1'b1;

          m_ip_payload_axis_tvalid_int = 1'b1;
          m_ip_payload_axis_tdata_int[7:0] = udp_source_port_reg[15:8];
          m_ip_payload_axis_tdata_int[15:8] = udp_source_port_reg[7:0];
          m_ip_payload_axis_tdata_int[23:16] = udp_dest_port_reg[15:8];
          m_ip_payload_axis_tdata_int[31:24] = udp_dest_port_reg[7:0];
          if (s_udp_dest_port == ROCE_UDP_PORT) begin
            m_ip_payload_axis_tdata_int[39:32] = udp_length_roce_reg[15:8];
            m_ip_payload_axis_tdata_int[47:40] = udp_length_roce_reg[7:0];
          end else begin
            m_ip_payload_axis_tdata_int[39:32] = udp_length_reg[15:8];
            m_ip_payload_axis_tdata_int[47:40] = udp_length_reg[7:0];
          end
          m_ip_payload_axis_tdata_int[55:48] = udp_checksum_reg[15:8];
          m_ip_payload_axis_tdata_int[63:56] = udp_checksum_reg[7:0];
          m_ip_payload_axis_tdata_int[511:64] = shift_udp_payload_axis_tdata[511:64];
          m_ip_payload_axis_tkeep_int = {shift_udp_payload_axis_tkeep[63:8], 8'hFF};

          s_udp_payload_axis_tready_next = m_ip_payload_axis_tready_int_early;

          word_count_next = s_udp_length - keep2count(m_ip_payload_axis_tkeep_int);

          if (s_udp_length - keep2count(m_ip_payload_axis_tkeep_int) == 16'd0) begin
            // have entire payload
            if (shift_udp_payload_axis_tlast) begin
              s_udp_hdr_ready_next = !m_ip_hdr_valid_next;
              s_udp_payload_axis_tready_next = 1'b0;
              m_ip_payload_axis_tlast_int = 1'b1;
              state_next = STATE_IDLE;
            end else begin
              store_last_word = 1'b1;
              s_udp_payload_axis_tready_next = shift_udp_payload_s_tready;
              m_ip_payload_axis_tvalid_int = 1'b0;
              state_next = STATE_WRITE_PAYLOAD_LAST;
            end
          end else begin
            if (shift_udp_payload_axis_tlast) begin
              // end of frame, but length does not match
              error_payload_early_termination_next = 1'b1;
              s_udp_payload_axis_tready_next = shift_udp_payload_s_tready;
              m_ip_payload_axis_tuser_int = 1'b1;
              state_next = STATE_WAIT_LAST;
            end else begin
              state_next = STATE_WRITE_PAYLOAD;
            end
          end
        end else begin
          state_next = STATE_WRITE_HEADER;
        end
      end
      STATE_WRITE_PAYLOAD: begin
        // write payload
        s_udp_payload_axis_tready_next = m_ip_payload_axis_tready_int_early && shift_udp_payload_s_tready;

        m_ip_payload_axis_tdata_int = shift_udp_payload_axis_tdata;
        m_ip_payload_axis_tkeep_int = shift_udp_payload_axis_tkeep;
        m_ip_payload_axis_tlast_int = shift_udp_payload_axis_tlast;
        m_ip_payload_axis_tuser_int = shift_udp_payload_axis_tuser;

        store_last_word = 1'b1;

        if (m_ip_payload_axis_tready_int_reg && shift_udp_payload_axis_tvalid) begin
          // word transfer through
          word_count_next = word_count_reg - 16'd64;
          transfer_in_save = 1'b1;
          m_ip_payload_axis_tvalid_int = 1'b1;
          //if (word_count_reg <= 64) begin
          if (word_count_reg - keep2count(m_ip_payload_axis_tkeep_int) == 16'd0) begin
            // have entire payload
            m_ip_payload_axis_tkeep_int = count2keep(word_count_reg);
            if (shift_udp_payload_axis_tlast) begin
              if (keep2count(shift_udp_payload_axis_tkeep) < word_count_reg[6:0]) begin
                // end of frame, but length does not match
                error_payload_early_termination_next = 1'b1;
                m_ip_payload_axis_tuser_int = 1'b1;
              end
              s_udp_payload_axis_tready_next = 1'b0;
              flush_save = 1'b1;
              s_udp_hdr_ready_next = !m_ip_hdr_valid_next;
              state_next = STATE_IDLE;
            end else begin
              m_ip_payload_axis_tvalid_int = 1'b0;
              state_next = STATE_WRITE_PAYLOAD_LAST;
            end
          end else begin
            if (shift_udp_payload_axis_tlast) begin
              // end of frame, but length does not match
              error_payload_early_termination_next = 1'b1;
              m_ip_payload_axis_tuser_int = 1'b1;
              s_udp_payload_axis_tready_next = 1'b0;
              flush_save = 1'b1;
              s_udp_hdr_ready_next = !m_ip_hdr_valid_next;
              state_next = STATE_IDLE;
            end else begin
              state_next = STATE_WRITE_PAYLOAD;
            end
          end
        end else begin
          state_next = STATE_WRITE_PAYLOAD;
        end
      end
      STATE_WRITE_PAYLOAD_LAST: begin
        // read and discard until end of frame
        s_udp_payload_axis_tready_next = m_ip_payload_axis_tready_int_early && shift_udp_payload_s_tready;

        //m_ip_payload_axis_tdata_int = shift_udp_payload_axis_tdata;
        //m_ip_payload_axis_tkeep_int = shift_udp_payload_axis_tkeep;
        m_ip_payload_axis_tdata_int = last_word_data_reg;
        m_ip_payload_axis_tkeep_int = last_word_keep_reg;
        m_ip_payload_axis_tlast_int = shift_udp_payload_axis_tlast;
        m_ip_payload_axis_tuser_int = shift_udp_payload_axis_tuser;

        if (m_ip_payload_axis_tready_int_reg && shift_udp_payload_axis_tvalid) begin
          transfer_in_save = 1'b1;
          if (shift_udp_payload_axis_tlast) begin
            s_udp_hdr_ready_next = !m_ip_hdr_valid_next;
            s_udp_payload_axis_tready_next = 1'b0;
            m_ip_payload_axis_tvalid_int = 1'b1;
            state_next = STATE_IDLE;
          end else begin
            state_next = STATE_WRITE_PAYLOAD_LAST;
          end
        end else begin
          state_next = STATE_WRITE_PAYLOAD_LAST;
        end
      end
      STATE_WAIT_LAST: begin
        // read and discard until end of frame
        s_udp_payload_axis_tready_next = shift_udp_payload_s_tready;

        if (shift_udp_payload_axis_tvalid) begin
          transfer_in_save = 1'b1;
          if (shift_udp_payload_axis_tlast) begin
            s_udp_hdr_ready_next = !m_ip_hdr_valid_next;
            s_udp_payload_axis_tready_next = 1'b0;
            state_next = STATE_IDLE;
          end else begin
            state_next = STATE_WAIT_LAST;
          end
        end else begin
          state_next = STATE_WAIT_LAST;
        end
      end
    endcase
  end

  always @(posedge clk) begin
    if (rst) begin
      state_reg <= STATE_IDLE;
      s_udp_hdr_ready_reg <= 1'b0;
      s_udp_payload_axis_tready_reg <= 1'b0;
      m_ip_hdr_valid_reg <= 1'b0;
      save_udp_payload_axis_tlast_reg <= 1'b0;
      shift_udp_payload_extra_cycle_reg <= 1'b0;
      busy_reg <= 1'b0;
      error_payload_early_termination_reg <= 1'b0;
    end else begin
      state_reg <= state_next;

      s_udp_hdr_ready_reg <= s_udp_hdr_ready_next;
      s_udp_payload_axis_tready_reg <= s_udp_payload_axis_tready_next;

      m_ip_hdr_valid_reg <= m_ip_hdr_valid_next;

      busy_reg <= state_next != STATE_IDLE;

      error_payload_early_termination_reg <= error_payload_early_termination_next;

      if (flush_save) begin
        save_udp_payload_axis_tlast_reg   <= 1'b0;
        shift_udp_payload_extra_cycle_reg <= 1'b0;
      end else if (transfer_in_save) begin
        save_udp_payload_axis_tlast_reg <= s_udp_payload_axis_tlast;
        shift_udp_payload_extra_cycle_reg <= s_udp_payload_axis_tlast && (s_udp_payload_axis_tkeep[63:56] != 0);
      end
    end

    word_count_reg <= word_count_next;

    // datapath
    if (store_udp_hdr) begin
      m_eth_dest_mac_reg <= s_eth_dest_mac;
      m_eth_src_mac_reg <= s_eth_src_mac;
      m_eth_type_reg <= s_eth_type;
      m_ip_version_reg <= s_ip_version;
      m_ip_ihl_reg <= s_ip_ihl;
      m_ip_dscp_reg <= s_ip_dscp;
      m_ip_ecn_reg <= s_ip_ecn;
      m_ip_length_reg <= s_udp_length + 20;
      m_ip_identification_reg <= s_ip_identification;
      m_ip_flags_reg <= s_ip_flags;
      m_ip_fragment_offset_reg <= s_ip_fragment_offset;
      m_ip_ttl_reg <= s_ip_ttl;
      m_ip_protocol_reg <= s_ip_protocol;
      m_ip_header_checksum_reg <= s_ip_header_checksum;
      m_ip_source_ip_reg <= s_ip_source_ip;
      m_ip_dest_ip_reg <= s_ip_dest_ip;
      m_is_roce_packet_reg <= s_udp_dest_port == ROCE_UDP_PORT;
      udp_source_port_reg <= s_udp_source_port;
      udp_dest_port_reg <= s_udp_dest_port;
      udp_length_reg <= s_udp_length;
      udp_checksum_reg <= s_udp_checksum;
      udp_length_roce_reg <= s_udp_length + 16'd4;
    end

    if (store_last_word) begin
      last_word_data_reg <= m_ip_payload_axis_tdata_int;
      last_word_keep_reg <= m_ip_payload_axis_tkeep_int;
    end

    if (transfer_in_save) begin
      save_udp_payload_axis_tdata_reg <= s_udp_payload_axis_tdata;
      save_udp_payload_axis_tkeep_reg <= s_udp_payload_axis_tkeep;
      save_udp_payload_axis_tuser_reg <= s_udp_payload_axis_tuser;
    end
  end

  // output datapath logic
  reg [511:0] m_ip_payload_axis_tdata_reg = 512'd0;
  reg [ 63:0] m_ip_payload_axis_tkeep_reg = 64'd0;
  reg m_ip_payload_axis_tvalid_reg = 1'b0, m_ip_payload_axis_tvalid_next;
  reg         m_ip_payload_axis_tlast_reg = 1'b0;
  reg         m_ip_payload_axis_tuser_reg = 1'b0;

  reg [511:0] temp_m_ip_payload_axis_tdata_reg = 512'd0;
  reg [ 63:0] temp_m_ip_payload_axis_tkeep_reg = 64'd0;
  reg temp_m_ip_payload_axis_tvalid_reg = 1'b0, temp_m_ip_payload_axis_tvalid_next;
  reg temp_m_ip_payload_axis_tlast_reg = 1'b0;
  reg temp_m_ip_payload_axis_tuser_reg = 1'b0;

  // datapath control
  reg store_ip_payload_int_to_output;
  reg store_ip_payload_int_to_temp;
  reg store_ip_payload_axis_temp_to_output;

  assign m_ip_payload_axis_tdata = m_ip_payload_axis_tdata_reg;
  assign m_ip_payload_axis_tkeep = m_ip_payload_axis_tkeep_reg;
  assign m_ip_payload_axis_tvalid = m_ip_payload_axis_tvalid_reg;
  assign m_ip_payload_axis_tlast = m_ip_payload_axis_tlast_reg;
  assign m_ip_payload_axis_tuser = m_ip_payload_axis_tuser_reg;

  // enable ready input next cycle if output is ready or if both output registers are empty
  assign m_ip_payload_axis_tready_int_early = m_ip_payload_axis_tready || (!temp_m_ip_payload_axis_tvalid_reg && !m_ip_payload_axis_tvalid_reg);

  always @* begin
    // transfer sink ready state to source
    m_ip_payload_axis_tvalid_next = m_ip_payload_axis_tvalid_reg;
    temp_m_ip_payload_axis_tvalid_next = temp_m_ip_payload_axis_tvalid_reg;

    store_ip_payload_int_to_output = 1'b0;
    store_ip_payload_int_to_temp = 1'b0;
    store_ip_payload_axis_temp_to_output = 1'b0;

    if (m_ip_payload_axis_tready_int_reg) begin
      // input is ready
      if (m_ip_payload_axis_tready | !m_ip_payload_axis_tvalid_reg) begin
        // output is ready or currently not valid, transfer data to output
        m_ip_payload_axis_tvalid_next  = m_ip_payload_axis_tvalid_int;
        store_ip_payload_int_to_output = 1'b1;
      end else begin
        // output is not ready, store input in temp
        temp_m_ip_payload_axis_tvalid_next = m_ip_payload_axis_tvalid_int;
        store_ip_payload_int_to_temp = 1'b1;
      end
    end else if (m_ip_payload_axis_tready) begin
      // input is not ready, but output is ready
      m_ip_payload_axis_tvalid_next = temp_m_ip_payload_axis_tvalid_reg;
      temp_m_ip_payload_axis_tvalid_next = 1'b0;
      store_ip_payload_axis_temp_to_output = 1'b1;
    end
  end

  always @(posedge clk) begin
    m_ip_payload_axis_tvalid_reg <= m_ip_payload_axis_tvalid_next;
    m_ip_payload_axis_tready_int_reg <= m_ip_payload_axis_tready_int_early;
    temp_m_ip_payload_axis_tvalid_reg <= temp_m_ip_payload_axis_tvalid_next;

    // datapath
    if (store_ip_payload_int_to_output) begin
      m_ip_payload_axis_tdata_reg <= m_ip_payload_axis_tdata_int;
      m_ip_payload_axis_tkeep_reg <= m_ip_payload_axis_tkeep_int;
      m_ip_payload_axis_tlast_reg <= m_ip_payload_axis_tlast_int;
      m_ip_payload_axis_tuser_reg <= m_ip_payload_axis_tuser_int;
    end else if (store_ip_payload_axis_temp_to_output) begin
      m_ip_payload_axis_tdata_reg <= temp_m_ip_payload_axis_tdata_reg;
      m_ip_payload_axis_tkeep_reg <= temp_m_ip_payload_axis_tkeep_reg;
      m_ip_payload_axis_tlast_reg <= temp_m_ip_payload_axis_tlast_reg;
      m_ip_payload_axis_tuser_reg <= temp_m_ip_payload_axis_tuser_reg;
    end

    if (store_ip_payload_int_to_temp) begin
      temp_m_ip_payload_axis_tdata_reg <= m_ip_payload_axis_tdata_int;
      temp_m_ip_payload_axis_tkeep_reg <= m_ip_payload_axis_tkeep_int;
      temp_m_ip_payload_axis_tlast_reg <= m_ip_payload_axis_tlast_int;
      temp_m_ip_payload_axis_tuser_reg <= m_ip_payload_axis_tuser_int;
    end

    if (rst) begin
      m_ip_payload_axis_tvalid_reg <= 1'b0;
      m_ip_payload_axis_tready_int_reg <= 1'b0;
      temp_m_ip_payload_axis_tvalid_reg <= 1'b0;
    end
  end

endmodule

`resetall
