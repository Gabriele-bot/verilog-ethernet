`resetall `timescale 1ns / 1ps `default_nettype none


module ip_query_mac (
    input wire clk,
    input wire rst,
    /*
     * IP header output
     */
    output wire         m_ip_hdr_valid,
    input  wire         m_ip_hdr_ready,
    output wire [ 47:0] m_ip_eth_dest_mac,
    output wire [ 47:0] m_ip_eth_src_mac,
    output wire [ 15:0] m_ip_eth_type,
    output wire [  5:0] m_ip_dscp,
    output wire [  1:0] m_ip_ecn,
    output wire [ 15:0] m_ip_length,
    output wire [  7:0] m_ip_ttl,
    output wire [  7:0] m_ip_protocol,
    output wire [ 31:0] m_ip_source_ip,
    output wire [ 31:0] m_ip_dest_ip,
    output wire         m_is_roce_packet,
    output wire         m_drop_packet,

    /*
     * ARP requests
     */
    output wire        arp_request_valid,
    input  wire        arp_request_ready,
    output wire [31:0] arp_request_ip,
    input  wire        arp_response_valid,
    output wire        arp_response_ready,
    input  wire        arp_response_error,
    input  wire [47:0] arp_response_mac,

    /*
     * IP header input
     */
    input  wire         s_ip_hdr_valid,
    output wire         s_ip_hdr_ready,
    input  wire [  5:0] s_ip_dscp,
    input  wire [  1:0] s_ip_ecn,
    input  wire [ 15:0] s_ip_length,
    input  wire [  7:0] s_ip_ttl,
    input  wire [  7:0] s_ip_protocol,
    input  wire [ 31:0] s_ip_source_ip,
    input  wire [ 31:0] s_ip_dest_ip,
    input  wire         s_is_roce_packet,
    /*
     * Status
     */
    output wire rx_busy,
    output wire tx_busy,
    output wire tx_error_arp_failed,

    /*
     * Configuration
     */
    input wire [47:0] local_mac,
    input wire [31:0] local_ip
);

    localparam [1:0] STATE_IDLE = 2'd0,  STATE_ARP_QUERY = 2'd1, STATE_SEND_HEADER = 2'd2, STATE_USE_CACHED_VALUE = 2'd3;

    reg [1:0] state_reg = STATE_IDLE, state_next;

    reg outgoing_ip_hdr_valid_reg = 1'b0, outgoing_ip_hdr_valid_next;
    wire outgoing_ip_hdr_ready;
    reg [47:0] outgoing_eth_dest_mac_reg = 48'h000000000000, outgoing_eth_dest_mac_next;

    reg [31:0] last_ip_addr_query_reg, last_ip_addr_query_next;
    reg [47:0] cached_mac_address_reg, cached_mac_address_next;

    reg s_ip_hdr_ready_reg = 1'b0, s_ip_hdr_ready_next;

    reg arp_request_valid_reg = 1'b0, arp_request_valid_next;

    reg arp_response_ready_reg = 1'b0, arp_response_ready_next;

    reg drop_packet_reg = 1'b0, drop_packet_next;

    assign s_ip_hdr_ready = s_ip_hdr_ready_reg;

    assign m_ip_hdr_valid    = outgoing_ip_hdr_valid_reg;
    assign outgoing_ip_hdr_ready = m_ip_hdr_ready;
    assign m_ip_eth_dest_mac = outgoing_eth_dest_mac_reg;
    assign m_ip_eth_src_mac  = local_mac;
    assign m_ip_eth_type     = 16'h800;
    assign m_ip_dscp         = s_ip_dscp;
    assign m_ip_ecn          = s_ip_ecn;
    assign m_ip_length       = s_ip_length;
    assign m_ip_ttl          = s_ip_ttl;
    assign m_ip_protocol     = s_ip_protocol;
    assign m_ip_source_ip    = s_ip_source_ip;
    assign m_ip_dest_ip      = s_ip_dest_ip;
    assign m_is_roce_packet  = s_is_roce_packet;
    assign m_drop_packet     = drop_packet_reg;

    assign arp_request_valid = arp_request_valid_reg;
    assign arp_request_ip = s_ip_dest_ip;
    assign arp_response_ready = arp_response_ready_reg;

    assign tx_error_arp_failed = arp_response_error;

    always @* begin
        state_next = STATE_IDLE;

        arp_request_valid_next = arp_request_valid_reg && !arp_request_ready;
        arp_response_ready_next = 1'b0;
        drop_packet_next = 1'b0;

        last_ip_addr_query_next = last_ip_addr_query_reg;
        cached_mac_address_next = cached_mac_address_reg;

        s_ip_hdr_ready_next = 1'b0;

        outgoing_ip_hdr_valid_next = outgoing_ip_hdr_valid_reg && !outgoing_ip_hdr_ready;
        outgoing_eth_dest_mac_next = outgoing_eth_dest_mac_reg;

        case (state_reg)
            STATE_IDLE: begin
                // wait for outgoing packet
                if (s_ip_hdr_valid) begin
                    if (s_ip_dest_ip == last_ip_addr_query_reg) begin
                        state_next = STATE_USE_CACHED_VALUE;
                    end else begin
                        // initiate ARP request
                        arp_request_valid_next = 1'b1;
                        last_ip_addr_query_next = arp_request_ip;
                        arp_response_ready_next = 1'b1;
                        state_next = STATE_ARP_QUERY;
                    end
                end else begin
                    state_next = STATE_IDLE;
                end
            end
            STATE_ARP_QUERY: begin
                arp_response_ready_next = 1'b1;

                if (arp_response_valid) begin
                    // wait for ARP reponse
                    if (arp_response_error) begin
                        // did not get MAC address; drop packet
                        s_ip_hdr_ready_next = 1'b1;
                        drop_packet_next = 1'b1;
                        state_next = STATE_SEND_HEADER;
                    end else begin
                        // got MAC address; send packet
                        s_ip_hdr_ready_next = 1'b1;
                        outgoing_ip_hdr_valid_next = 1'b1;
                        outgoing_eth_dest_mac_next = arp_response_mac;
                        cached_mac_address_next = arp_response_mac;
                        state_next = STATE_SEND_HEADER;
                    end
                end else begin
                    state_next = STATE_ARP_QUERY;
                end
            end
            STATE_SEND_HEADER: begin
                if (m_ip_hdr_valid && m_ip_hdr_ready) begin
                    state_next = STATE_IDLE;
                end else begin
                    state_next = STATE_SEND_HEADER;
                end
            end
            STATE_USE_CACHED_VALUE: begin
                // got MAC address; send packet
                s_ip_hdr_ready_next = 1'b1;
                outgoing_ip_hdr_valid_next = 1'b1;
                outgoing_eth_dest_mac_next = cached_mac_address_reg;
                state_next = STATE_SEND_HEADER;
            end
        endcase
    end

    always @(posedge clk) begin
        if (rst) begin
            state_reg <= STATE_IDLE;
            arp_request_valid_reg <= 1'b0;
            arp_response_ready_reg <= 1'b0;
            drop_packet_reg <= 1'b0;
            s_ip_hdr_ready_reg <= 1'b0;
            outgoing_ip_hdr_valid_reg <= 1'b0;

            last_ip_addr_query_reg <= {8'hFF, 8'hFF, 8'hFF, 8'hFF};
            cached_mac_address_reg <= 48'h00_00_00_00_00_00;

        end else begin
            state_reg <= state_next;

            arp_request_valid_reg <= arp_request_valid_next;
            arp_response_ready_reg <= arp_response_ready_next;
            drop_packet_reg <= drop_packet_next;

            last_ip_addr_query_reg <= last_ip_addr_query_next;
            cached_mac_address_reg <= cached_mac_address_next;

            s_ip_hdr_ready_reg <= s_ip_hdr_ready_next;

            outgoing_ip_hdr_valid_reg <= outgoing_ip_hdr_valid_next;

        end

        outgoing_eth_dest_mac_reg <= outgoing_eth_dest_mac_next;
    end

endmodule

`resetall
