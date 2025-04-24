/*
 * Basic Ethernet Switch P4 Program
 * This program implements a minimal Layer 2 switch using the V1Model architecture.
 */

#include <core.p4>
#include <v1model.p4>

/************** Constants **************/
const bit<16> TYPE_IPV4 = 0x0800;
typedef bit<48> macAddr_t;
typedef bit<9>  port_t;

/************** Data Types **************/
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

/************** Metadata Structs **************/
struct metadata { 
    // Empty metadata (required by parser/control signatures)
}

struct headers {
    ethernet_t ethernet;
}

/************** Parser **************/
parser MyParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    state start {
        transition parse_ethernet;
    }
    
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition accept;
    }
}

/************** Checksum Controls **************/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { /* No checksum verification */ }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { /* No checksum computation */ }
}

/************** Ingress Control **************/
control MyIngress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action forward(port_t egress_port) {
        standard_metadata.egress_spec = egress_port;
    }
    
    table dmac_table {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    apply {
        if (hdr.ethernet.isValid()) {
            dmac_table.apply();
        } else {
            drop();
        }
    }
}

/************** Egress Control **************/
control MyEgress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    apply { /* No egress processing */ }
}

/************** Deparser **************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
    }
}

/************** Main Pipeline **************/
V1Switch(
    MyParser(),              // Parser
    MyVerifyChecksum(),      // Checksum verification
    MyIngress(),             // Ingress processing
    MyEgress(),              // Egress processing
    MyComputeChecksum(),     // Checksum computation
    MyDeparser()             // Deparser
) main;
