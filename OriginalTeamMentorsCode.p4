#include <core.p4>

const bit<9> DROP_PORT = 0;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

struct metadata_t {}
struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    bool has_ethernet;
    bool has_ipv4;
}

parser MyParser(packet_in packet,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        hdr.has_ethernet = true;
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        hdr.has_ipv4 = true;
        transition accept;
    }
}

control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        standard_metadata.egress_spec = DROP_PORT;
    }

    table block_all {
        actions = {
            drop;
        }
        size = 1;
        default_action = drop();
    }

    apply {
        block_all.apply();
    }
}

control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyDeparser(packet_out packet,
                   in headers_t hdr) {
    apply {
        if (hdr.has_ethernet) {
            packet.emit(hdr.ethernet);
        }
        if (hdr.has_ipv4) {
            packet.emit(hdr.ipv4);
        }
    }
}

package MySwitch(ParserImpl, IngressImpl, EgressImpl, DeparserImpl)(
    MyParser ParserImpl,
    MyIngress IngressImpl,
    MyEgress EgressImpl,
    MyDeparser DeparserImpl
);

MySwitch() main = MySwitch(
    MyParser(),
    MyIngress(),
    MyEgress(),
    MyDeparser()
);
