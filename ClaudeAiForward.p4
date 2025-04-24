/* 
 * Basic L2/L3 Switch with v1model architecture
 * Features:
 * - Ethernet and IPv4 packet handling with ARP support
 * - L3 (IPv4) and L2 (Ethernet) forwarding tables
 * - L3 forwarding priority over L2
 * - Actions for forwarding, broadcasting, and dropping
 * - Default behaviors for unknown destinations
 * - IPv4 checksum recalculation
 */

#include <core.p4>
#include <v1model.p4>

// Type definitions
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<9>  port_id_t;

// Constants
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP  = 0x0806;

// Header definitions
header ethernet_h {
    mac_addr_t  dst_addr;
    mac_addr_t  src_addr;
    bit<16>     ether_type;
}

header ipv4_h {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      dscp_ecn;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     header_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header arp_h {
    bit<16>     hw_type;
    bit<16>     proto_type;
    bit<8>      hw_addr_len;
    bit<8>      proto_addr_len;
    bit<16>     opcode;
    mac_addr_t  sender_hw_addr;
    ipv4_addr_t sender_proto_addr;
    mac_addr_t  target_hw_addr;
    ipv4_addr_t target_proto_addr;
}

// Metadata structure
struct metadata_t {
    bit<1> l3_forwarding_performed;  // Indicates if L3 forwarding was applied
}

// Headers structure
struct headers_t {
    ethernet_h ethernet;
    ipv4_h     ipv4;
    arp_h      arp;
}

// Parser implementation
parser SwitchParser(packet_in packet,
                    out headers_t hdr,
                    inout metadata_t meta,
                    inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
}

// Checksum verification control
control SwitchVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        verify_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp_ecn,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            },
            hdr.ipv4.header_checksum,
            HashAlgorithm.csum16);
    }
}

// Ingress control
control SwitchIngress(inout headers_t hdr,
                      inout metadata_t meta,
                      inout standard_metadata_t standard_metadata) {
    
    // Initialize metadata
    action init_metadata() {
        meta.l3_forwarding_performed = 0;
    }
    
    // L3 forwarding actions
    action forward_ipv4(port_id_t egress_port) {
        standard_metadata.egress_spec = egress_port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        meta.l3_forwarding_performed = 1;
    }
    
    action drop_ipv4() {
        mark_to_drop(standard_metadata);
        meta.l3_forwarding_performed = 1;
    }
    
    // L2 forwarding actions
    action forward_l2(port_id_t egress_port) {
        standard_metadata.egress_spec = egress_port;
    }
    
    action broadcast_packet() {
        standard_metadata.mcast_grp = 1;  // Using multicast group 1 for broadcast
    }
    
    action drop_packet() {
        mark_to_drop(standard_metadata);
    }
    
    // IPv4 routing table
    table ipv4_routing {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            forward_ipv4;
            drop_ipv4;
            NoAction;
        }
        size = 1024;
        default_action = drop_ipv4();
    }
    
    // MAC address table
    table mac_forwarding {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = {
            forward_l2;
            broadcast_packet;
            drop_packet;
            NoAction;
        }
        size = 1024;
        default_action = broadcast_packet();
    }
    
    apply {
        // Initialize metadata
        init_metadata();
        
        // First try L3 (IPv4) forwarding
        if (hdr.ipv4.isValid()) {
            ipv4_routing.apply();
        }
        
        // If L3 forwarding wasn't applied, try L2 forwarding
        if (meta.l3_forwarding_performed == 0) {
            mac_forwarding.apply();
        }
    }
}

// Egress control
control SwitchEgress(inout headers_t hdr,
                     inout metadata_t meta,
                     inout standard_metadata_t standard_metadata) {
    apply { }  // No egress processing needed
}

// Checksum computation control
control SwitchComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp_ecn,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            },
            hdr.ipv4.header_checksum,
            HashAlgorithm.csum16);
    }
}

// Deparser
control SwitchDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.arp);
    }
}

// Instantiate the switch
V1Switch(
    SwitchParser(),
    SwitchVerifyChecksum(),
    SwitchIngress(),
    SwitchEgress(),
    SwitchComputeChecksum(),
    SwitchDeparser()
) main;
