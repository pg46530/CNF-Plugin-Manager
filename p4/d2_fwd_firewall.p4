/* SPDX-License-Identifier: ANCL-1.0
 * Copyright (c) 2026  jfpereira <d12267@di.uminho.pt> — di.uminho.pt
 * Academic use only · no commercial use · see LICENSE
 * AI-assisted development: Claude (Anthropic)
 */

#include <core.p4>
#include <v1model.p4>
#include "headers.p4"

// CONSTs ***********************************************************************

const bit<8> PROTO_TCP = 0x06;
const bit<8> PROTO_UDP = 0x11;
const bit<9> LAN_PORT       = 1;
const bit<9> LAN_PORT2      = 2;
const bit<9> ARP_PROXY_PORT = 3;
const bit<9> DHCP_PORT      = 4;
const bit<16> DHCP_SERVER_PORT = 67;
const bit<16> DHCP_CLIENT_PORT = 68;

#define BLOOM_FILTER_ENTRIES   4096
#define BLOOM_FILTER_BIT_WIDTH 1

// Generic transport header — srcPort and dstPort occupy the same
// bit positions in both TCP and UDP. Valid here because the firewall
// only reads these fields, never modifies them.
header transport_t {
    bit<16> srcPort;
    bit<16> dstPort;
}

// STRUCTURES *******************************************************************

struct metadata {
    macAddr_t nextHopMac;
}

struct headers {
    ethernet_t  ether;
    arp_t       arp;
    ipv4_t      ipv4;
    transport_t transport;
    udp_tail_t  udp_tail;
    dhcp_t      dhcp;
}

// PARSER ***********************************************************************

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ether);
        transition select(hdr.ether.type) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP:  parse_arp;
            default:   accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_transport;
            PROTO_UDP: parse_udp;
            default:   accept;
        }
    }

    state parse_transport {
        packet.extract(hdr.transport);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.transport);
        transition select(hdr.transport.dstPort) {
            DHCP_SERVER_PORT: skip_udp_tail;
            DHCP_CLIENT_PORT: skip_udp_tail;
            default: accept;
        }
    }

    state skip_udp_tail {
        packet.extract(hdr.udp_tail);
        transition parse_dhcp;
    }

    state parse_dhcp {
        packet.extract(hdr.dhcp);
        transition accept;
    }
}

// CHECKSUM VERIFICATION ********************************************************

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

// INGRESS **********************************************************************

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t std_meta) {

    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloomFilter1;
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloomFilter2;

    bit<32> regPosOne;
    bit<32> regPosTwo;
    bit<1>  regValOne;
    bit<1>  regValTwo;

    counter(1, CounterType.packets_and_bytes) forwardedCounter;
    counter(1, CounterType.packets_and_bytes) droppedCounter;

    action drop() {
        mark_to_drop(std_meta);
        droppedCounter.count(0);
    }

    action computeHashes(ip4Addr_t ipSrc, ip4Addr_t ipDst,
                         bit<16> portSrc, bit<16> portDst) {
        hash(regPosOne, HashAlgorithm.crc16, (bit<32>)0,
             { ipSrc, ipDst, hdr.ipv4.protocol, portSrc, portDst },
             (bit<32>)BLOOM_FILTER_ENTRIES);

        hash(regPosTwo, HashAlgorithm.crc32, (bit<32>)0,
             { ipSrc, ipDst, hdr.ipv4.protocol, portSrc, portDst },
             (bit<32>)BLOOM_FILTER_ENTRIES);
    }

    action forward(bit<9> egressPort, macAddr_t nextHopMac) {
        std_meta.egress_spec = egressPort;
        meta.nextHopMac = nextHopMac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4Lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = {
            forward;
            drop;
        }
        size = 256;
        default_action = drop;
    }

    action rewriteMacs(macAddr_t srcMac) {
        hdr.ether.srcAddr = srcMac;
        hdr.ether.dstAddr = meta.nextHopMac;
    }

    table internalMacLookup {
        key = { std_meta.egress_spec: exact; }
        actions = {
            rewriteMacs;
            drop;
        }
        size = 256;
        default_action = drop;
    }

    action forward_to_port(bit<9> port) {
        std_meta.egress_spec = port;
    }

    // routes ARP replies from the proxy back to the correct LAN port
    // controller installs: 10.0.1.0/24 -> port 1, 10.0.2.0/24 -> port 2
    table arpRoute {
        key = { hdr.arp.tpa: lpm; }
        actions = {
            forward_to_port;
            drop;
        }
        size = 16;
        default_action = drop;
    }

    table dhcpRoute {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = {
            forward_to_port;
            drop;
        }
        size = 16;
        default_action = drop;
    }

    apply {
        bool do_forward = false;

        if (hdr.arp.isValid()) {
            // ARP bypasses the firewall — redirect to the proxy or back to the LAN
            if (std_meta.ingress_port == LAN_PORT || std_meta.ingress_port == LAN_PORT2) {
                // request from a host → send to ARP proxy cNF
                forward_to_port(ARP_PROXY_PORT);
            } else if (std_meta.ingress_port == ARP_PROXY_PORT) {
                // reply from proxy → route back to the correct LAN
                arpRoute.apply();
            } else {
                drop();
            }
        } else if (hdr.dhcp.isValid()) {
            if (std_meta.ingress_port == LAN_PORT2) {
                forward_to_port(DHCP_PORT);
            } else if (std_meta.ingress_port == DHCP_PORT) {
                dhcpRoute.apply();
            } else {
                drop();
            }
        } else if (!hdr.ipv4.isValid()) {
            drop();
        } else if (!hdr.transport.isValid()) {
            // non-TCP/UDP traffic is not tracked by the firewall — drop
            drop();
        } else {
            if (ipv4Lpm.apply().hit) {
                if (std_meta.ingress_port == LAN_PORT) {
                    // outbound: record this flow in the bloom filter
                    computeHashes(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr,
                                  hdr.transport.srcPort, hdr.transport.dstPort);
                    bloomFilter1.write(regPosOne, 1);
                    bloomFilter2.write(regPosTwo, 1);
                    do_forward = true;
                } else {
                    // inbound: only allow responses to LAN-initiated flows
                    computeHashes(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr,
                                  hdr.transport.dstPort, hdr.transport.srcPort);
                    bloomFilter1.read(regValOne, regPosOne);
                    bloomFilter2.read(regValTwo, regPosTwo);
                    if (regValOne == 1 && regValTwo == 1) {
                        do_forward = true;
                    } else {
                        drop();
                    }
                }
            }
        }

        if (do_forward) {
            internalMacLookup.apply();
            forwardedCounter.count(0);
        }
    }
}

// EGRESS ***********************************************************************

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t std_meta) {
    apply { }
}

// CHECKSUM COMPUTATION *********************************************************

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
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
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

// DEPARSER *********************************************************************

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ether);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.transport);
        packet.emit(hdr.udp_tail);
        packet.emit(hdr.dhcp);
    }
}

// SWITCH ***********************************************************************

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
