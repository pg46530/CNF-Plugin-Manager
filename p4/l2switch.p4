/* SPDX-License-Identifier: ANCL-1.0
 * Copyright (c) 2026  jfpereira <d12267@di.uminho.pt> — di.uminho.pt
 * Academic use only · no commercial use · see LICENSE
 * AI-assisted development: Claude (Anthropic)
 */

#include <core.p4>
#include <v1model.p4>
#include "headers.p4"

// EtherType used to identify CPU-bound packets (clone to controller)
const bit<16> L2_LEARN_ETHER_TYPE = 0x1234;

// STRUCTURES ***********************************************************************

// cpu_t is prepended to the packet in egress when it is cloned to the CPU port.
// The controller reads srcAddr and ingress_port to learn the MAC-to-port mapping.
header cpu_t {
    macAddr_t srcAddr;
    bit<16>   ingress_port;  // cast from bit<9>; read by controller as big-endian int
}

struct metadata {
    @field_list(0)       // preserved when the packet is cloned to the CPU port
    bit<9> ingress_port; // saved in ingress, used to build cpu_t in egress
}

struct headers {
    ethernet_t eth;
    cpu_t      cpu;
}

// PARSER ***************************************************************************

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.eth);
        transition accept;
    }
}

// CHECKSUM VERIFICATION ************************************************************

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

// INGRESS **************************************************************************
//
// Two tables, one pass:
//
//   sMacLookup (key = srcAddr)
//     miss → source MAC unknown: clone packet to CPU so the controller can learn it
//     hit  → source MAC already known: NoAction
//
//   dMacLookup (key = dstAddr)
//     miss → destination MAC unknown: flood via multicast group 1
//     hit  → destination MAC known: forward to the correct port

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t std_meta) {

    action clone_to_cpu() {
        meta.ingress_port = std_meta.ingress_port;
        clone_preserving_field_list(CloneType.I2E, 100, 0);
    }

    table sMacLookup {
        key     = { hdr.eth.srcAddr : exact; }
        actions = { clone_to_cpu; NoAction; }
        size    = 512;
        default_action = clone_to_cpu;
    }

    action forward(bit<9> egress_port) {
        std_meta.egress_spec = egress_port;
    }

    table dMacLookup {
        key     = { hdr.eth.dstAddr : exact; }
        actions = { forward; NoAction; }
        size    = 512;
        default_action = NoAction;
    }

    apply {
        if (hdr.eth.isValid()) {
            sMacLookup.apply();
            if (!dMacLookup.apply().hit) {
                std_meta.mcast_grp = 1;  // unknown destination: flood
            }
        } else {
            mark_to_drop(std_meta);
        }
    }
}

// EGRESS ***************************************************************************

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t std_meta) {

    action drop() {
        mark_to_drop(std_meta);
    }

    apply {
        if (std_meta.instance_type == 1) {
            // This is the clone destined for the CPU port.
            // Build the cpu_t header so the controller can extract
            // srcAddr and ingress_port without inspecting raw metadata.
            hdr.cpu.setValid();
            hdr.cpu.srcAddr      = hdr.eth.srcAddr;
            hdr.cpu.ingress_port = (bit<16>)meta.ingress_port;
            hdr.eth.type         = L2_LEARN_ETHER_TYPE;
            // Truncate to exactly 22 bytes:
            //   14 (ethernet_t) + 8 (cpu_t) = 22
            truncate((bit<32>)22);
        }
        // Prevent a multicast copy from being sent back out the port it arrived on
        if (std_meta.egress_port == std_meta.ingress_port) {
            drop();
        }
    }
}

// CHECKSUM COMPUTATION *************************************************************

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

// DEPARSER *************************************************************************

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.eth);
        packet.emit(hdr.cpu);  // only emitted when hdr.cpu.setValid() was called
    }
}

// SWITCH ***************************************************************************

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
