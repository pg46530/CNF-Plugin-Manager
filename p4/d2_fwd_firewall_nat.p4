/* SPDX-License-Identifier: ANCL-1.0
 * Copyright (c) 2026  jfpereira <d12267@di.uminho.pt> — di.uminho.pt
 * Academic use only · no commercial use · see LICENSE
 * AI-assisted development: Claude (Anthropic)
 */

#include <core.p4>
#include <v1model.p4>
#include "headers.p4"

// CONSTs ***********************************************************************

const bit<8>  PROTO_TCP = 0x06;
const bit<8>  PROTO_UDP = 0x11;
const bit<9>  LAN_PORT  = 1;

// Think of this as the "public IP" your ISP assigns to your home router.
// All LAN hosts appear to the internet as this single address — just like
// every device in your home appears as your router's public IP to external servers.
// It lives outside both LAN scopes (10.0.1.x and 10.0.2.x) to avoid any ambiguity.
const ip4Addr_t NAT_EXT_IP = 0xC0A86464;   // 192.168.100.100

#define BLOOM_FILTER_ENTRIES   4096
#define BLOOM_FILTER_BIT_WIDTH 1

// SNAT hash table size: 55536 entries map to external ports 10000–65535.
// (55536 + 10000 = 65536, covering the full upper port range.)
#define SNAT_MAP_ENTRIES  55536
#define SNAT_PORT_OFFSET  10000

// NOTE: tcp_t and udp_t are declared here instead of headers.p4 because NAT
// must modify port fields and recalculate checksums. A generic transport_t
// header (as used in d2_fwd_firewall.p4) cannot access the checksum field —
// full protocol-specific headers are required here.

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

// STRUCTURES *******************************************************************

struct metadata {
    macAddr_t nextHopMac;
    // TODO: add fields to hold the source and destination transport ports
    //       extracted from the TCP or UDP header.
    //       NAT actions and the bloom filter both need these values.
    //       Hint: two bit<16> fields, one for each direction.
    //
    // TODO: add a field to hold the pre-computed TCP segment length.
    //       update_checksum does not allow inline arithmetic expressions —
    //       compute totalLen - 20 before MyComputeChecksum runs and pass
    //       the result via metadata.
    //       Valid locations: the parser (after extracting ipv4) or MyIngress.
}

struct headers {
    ethernet_t ether;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
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
            default:   accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            default:   accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
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

    // Bloom filter — same as d2_fwd_firewall.p4
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloomFilter1;
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloomFilter2;

    bit<32> regPosOne;
    bit<32> regPosTwo;
    bit<1>  regValOne;
    bit<1>  regValTwo;

    // SNAT state — one entry per possible hash index.
    // Each slot packs the original LAN source address and port into 48 bits:
    //
    //   bits [47:16]  original ip.src   (32 bits)
    //   bits [15:0]   original transp.src (16 bits)
    //
    // P4 registers cannot store structs, so both fields share one bit<48> value.
    // On write: use the ++ concatenation operator to pack them together.
    // On read:  use bit slicing [47:16] / [15:0] to unpack them.
    //
    // The external mapped port = hash index + SNAT_PORT_OFFSET, keeping all
    // mapped ports in the range [10000, 65535].
    register<bit<48>>(SNAT_MAP_ENTRIES) snatOrig;

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

    // TODO: implement doSnat
    // This action is called on outbound packets (LAN → WAN).
    // It must:
    //   1. Hash the 5-tuple (srcAddr, dstAddr, protocol, srcPort, dstPort) with
    //      HashAlgorithm.crc32 to derive a stable index in [0, SNAT_MAP_ENTRIES-1].
    //      Including ip.proto ensures TCP and UDP flows with the same addresses
    //      and ports map to different indices.
    //   2. Pack and store the original (hdr.ipv4.srcAddr, transportSrcPort)
    //      into snatOrig[index] using the ++ operator.
    //   3. Rewrite hdr.ipv4.srcAddr to NAT_EXT_IP.
    //   4. Rewrite the transport source port to: index + SNAT_PORT_OFFSET.
    action doSnat() {
        // TODO
    }

    // TODO: implement doSnatReverse
    // This action is called on inbound return traffic (WAN → LAN).
    // The destination port of the return packet IS the mapped external port
    // assigned by doSnat: mapped_port = index + SNAT_PORT_OFFSET.
    // Subtracting SNAT_PORT_OFFSET recovers the original register index.
    //
    // It must:
    //   1. Compute the register index from meta.transportDstPort.
    //   2. Read snatOrig[index] into a bit<48> local variable.
    //   3. If the stored value is non-zero (slot was written), unpack it:
    //        bits [47:16] → restore as hdr.ipv4.dstAddr
    //        bits [15:0]  → restore as hdr.tcp/udp.dstPort
    //                       AND update meta.transportDstPort
    //                       (the bloom filter check needs the restored port)
    //
    // !! BMv2 constraint: register.read() cannot be inside an if/else in an action.
    //    Move the (meta.transportDstPort >= SNAT_PORT_OFFSET) guard to the apply
    //    block and call this action only when the guard passes.
    action doSnatReverse() {
        // TODO
    }

    // TODO: implement doPortForward
    // This action is called on inbound new connections matching a port forwarding rule.
    // It must rewrite hdr.ipv4.dstAddr and the transport layer dstPort.
    action doPortForward(ip4Addr_t dstIp, bit<16> dstPort) {
        // TODO
    }

    // Port forwarding rules — installed by the controller at startup via YAML config.
    // Each entry maps one (protocol, external port) pair to one internal host IP and port.
    // TCP and UDP rules are independent: port 80/TCP and port 80/UDP are separate entries.
    table portForwarding {
        key = {
            // TODO: which fields identify a port-forwarded packet?
            // Hint: the trigger is the destination port on inbound traffic.
            //       Should TCP and UDP port forwarding rules be independent?
        }
        actions = {
            doPortForward;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    // TODO: implement doReverseDnat
    // This action handles the return leg of a DNAT (port-forwarded) session.
    //
    // Problem: when h1:22 replies to a WAN client that connected via port forwarding,
    // the reply arrives on LAN_PORT with srcAddr=10.0.1.1 and srcPort=22.
    // Without this table, doSnat() would assign a random mapped port and the WAN
    // client would reject the reply (wrong source address — connection mismatch).
    //
    // Solution: rewrite srcAddr and srcPort back to the external values the WAN
    // client originally connected to, so the reply appears to come from NAT_EXT_IP
    // on the expected external port.
    //
    // Each entry mirrors a portForwarding entry in reverse:
    //   portForwarding:  (proto, extPort)          → (intIp,      intPort)
    //   dnatReturn:      (proto, intIp, intPort)    → (NAT_EXT_IP, extPort)
    action doReverseDnat(ip4Addr_t srcIp, bit<16> srcPort) {
        // TODO
    }

    table dnatReturn {
        key = {
            // TODO: which fields uniquely identify the return leg of a DNAT session?
            // Hint: you need to identify which internal host and port is replying,
            //       and whether it is TCP or UDP.
        }
        actions = {
            doReverseDnat;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    apply {
        bool do_forward    = false;
        bool ready_for_lpm = false;

        if (!hdr.ipv4.isValid()) {
            drop();
        } else if (!hdr.tcp.isValid() && !hdr.udp.isValid()) {
            drop();
        } else {
            // Extract transport ports into metadata.
            if (hdr.tcp.isValid()) {
                // TODO: fill meta.transportSrcPort and meta.transportDstPort
            } else {
                // TODO: fill meta.transportSrcPort and meta.transportDstPort
            }

            // Pre-compute TCP segment length for the checksum control.
            // update_checksum does not allow inline arithmetic expressions — only
            // plain variables or header fields. This can also be computed in the
            // parser right after extracting the IPv4 header, since totalLen is
            // available there and NAT never modifies packet lengths.
            // TODO: assign meta.tcpLen (if not already set in the parser)

            // TODO: implement the NAT + firewall pipeline.
            //
            // Your implementation must handle the following cases:
            //
            //   Case 1 — Outbound (LAN → WAN):
            //     - Check dnatReturn first: if hit, rewrite src and skip SNAT.
            //     - Otherwise: record the flow in the bloom filter, then apply SNAT.
            //     - Set ready_for_lpm = true.
            //
            //   Case 2 — Inbound new connection (WAN → LAN, port forwarding):
            //     - Check portForwarding table.
            //     - If hit: apply DNAT, set ready_for_lpm = true.
            //
            //   Case 3 — Inbound return traffic (WAN → LAN, response to a LAN flow):
            //     - Guard: only proceed if dstPort is in the SNAT mapped range.
            //     - Apply doSnatReverse to restore original dstAddr and dstPort.
            //     - Check the bloom filter (reversed 5-tuple).
            //     - If bloom hit: set ready_for_lpm = true. Otherwise: drop.
            //
            //   Case 4 — Inbound with no matching rule: drop.
            //
            // Think before you code:
            //   T1. Does the order of NAT and firewall operations matter? Justify.
            //   T2. Should the bloom filter check apply to DNAT (port-forwarded) traffic?
            //       Why or why not?
            //   T3. Why must ipv4Lpm be applied AFTER NAT rewrites rather than before?

            // Apply ipv4Lpm exactly once — after all NAT rewrites are complete.
            // (P4 does not allow the same table to be applied more than once per
            // control block, even in mutually exclusive branches.)
            if (ready_for_lpm) {
                if (ipv4Lpm.apply().hit) {
                    do_forward = true;
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
// Scaffold provided — NAT modifies IP addresses and transport ports, so all
// three checksums (IPv4, TCP, UDP) must be recalculated after any rewrite.

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // IPv4 header checksum
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

        // TCP checksum — covers a pseudo-header derived from the IP header,
        // the full TCP header, and the TCP payload.
        // Pseudo-header: srcAddr, dstAddr, zero byte, protocol, TCP segment length.
        // meta.tcpLen must be set before this point (parser or MyIngress) —
        // update_checksum forbids inline arithmetic expressions in the field list.
        update_checksum_with_payload(
            hdr.tcp.isValid(),
            { hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr,
              8w0,
              hdr.ipv4.protocol,
              meta.tcpLen,
              hdr.tcp.srcPort,
              hdr.tcp.dstPort,
              hdr.tcp.seqNo,
              hdr.tcp.ackNo,
              hdr.tcp.dataOffset,
              hdr.tcp.res,
              hdr.tcp.flags,
              hdr.tcp.window,
              hdr.tcp.urgentPtr },
            hdr.tcp.checksum,
            HashAlgorithm.csum16);

        // UDP checksum — same pseudo-header structure as TCP.
        // UDP length field serves as both the pseudo-header segment length
        // and the UDP header length field.
        update_checksum_with_payload(
            hdr.udp.isValid(),
            { hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr,
              8w0,
              hdr.ipv4.protocol,
              hdr.udp.length,
              hdr.udp.srcPort,
              hdr.udp.dstPort,
              hdr.udp.length },
            hdr.udp.checksum,
            HashAlgorithm.csum16);
    }
}

// DEPARSER *********************************************************************

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ether);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
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
