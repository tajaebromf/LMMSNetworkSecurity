#include <v1model.p4>

// ---------------------------- Headers ----------------------------
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> ethType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

// ---------------------------- Metadata ----------------------------
struct metadata_t {
    bit<9> egress_port;
}

// ---------------------------- Parsed Headers ----------------------------
struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

// ---------------------------- Parser ----------------------------
parser MyParser(packet_in packet,
                out headers_t hdr,
                out metadata_t meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

// ---------------------------- Checksum Verification ----------------------------
control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { /* no-op */ }
}

// ---------------------------- Ingress ----------------------------
action forward(bit<9> port) {
    standard_metadata.egress_spec = port;
}

action broadcast() {
    standard_metadata.egress_spec = 0xFFFF;
}

action drop() {
    mark_to_drop(standard_metadata);
}

table ethernet_exact {
    key = {
        hdr.ethernet.dstAddr: exact;
    }
    actions = {
        forward;
        broadcast;
        drop;
        NoAction;
    }
    size = 1024;
}

table ipv4_filter {
    key = {
        hdr.ipv4.srcAddr: exact;
        hdr.ipv4.dstAddr: exact;
    }
    actions = {
        forward;
        drop;
        NoAction;
    }
    size = 1024;
}

control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_filter.apply();
        } else {
            ethernet_exact.apply();
        }
    }
}

// ---------------------------- Egress ----------------------------
control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    apply { /* no-op */ }
}

// ---------------------------- Checksum Computation ----------------------------
control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        if (hdr.ipv4.isValid()) {
            update_checksum(
                hdr.ipv4.hdrChecksum,
                { hdr.ipv4.version,
                  hdr.ipv4.ihl,
                  hdr.ipv4.diffserv,
                  hdr.ipv4.totalLen,
                  hdr.ipv4.identification,
                  hdr.ipv4.flags,
                  hdr.ipv4.fragOffset,
                  hdr.ipv4.ttl,
                  hdr.ipv4.protocol,
                  hdr.ipv4.srcAddr,
                  hdr.ipv4.dstAddr },
                HashAlgorithm.csum16
            );
        }
    }
}

// ---------------------------- Deparser ----------------------------
control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        if (hdr.ipv4.isValid()) {
            packet.emit(hdr.ipv4);
        }
    }
}

// ---------------------------- Main Pipeline ----------------------------
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
