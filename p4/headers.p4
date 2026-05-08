/* SPDX-License-Identifier: ANCL-1.0
 * Copyright (c) 2026  jfpereira <d12267@di.uminho.pt> — di.uminho.pt
 * Academic use only · no commercial use · see LICENSE
 * AI-assisted development: Claude (Anthropic)
 */

// TYPEDEFs

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

// CONSTs

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP  = 0x0806;

// HEADERs

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   type;
}

header arp_t {
    bit<16>   htype;  // hardware type (1 = Ethernet)
    bit<16>   ptype;  // protocol type (0x0800 = IPv4)
    bit<8>    hlen;   // hardware address length (6)
    bit<8>    plen;   // protocol address length (4)
    bit<16>   oper;   // operation (1 = request, 2 = reply)
    macAddr_t sha;    // sender hardware address
    ip4Addr_t spa;    // sender protocol address
    macAddr_t tha;    // target hardware address
    ip4Addr_t tpa;    // target protocol address
}

// The remaining two fields of a UDP header after srcPort and dstPort.
// transport_t extracts only the first 4 bytes of a UDP/TCP header (srcPort + dstPort).
// After extract(hdr.transport), the parser cursor sits 4 bytes into the UDP header.
// These 4 bytes (length + checksum) must be extracted separately to re-align the cursor
// before the payload (e.g. BOOTP/DHCP) can be extracted.
// The deparser must emit both transport_t and udp_tail_t to keep the packet well-formed.
header udp_tail_t {
    bit<16> length;
    bit<16> checksum;
}

// DHCP header — DHCP reuses the BOOTP wire format (RFC 951 / RFC 2131).
// We parse the full 236-byte fixed portion to demonstrate that P4 can reach
// application-layer headers — the pipeline uses the op field to distinguish
// client→server (op=1) from server→client (op=2) traffic.
// Note: the same forwarding decision could be made with port + ingress port checks
// alone (transport_t is sufficient); parsing dhcp_t is an educational choice, not
// a requirement.
// Parsing stops before the variable-length options field (DHCP magic cookie 0x63825363).
header dhcp_t {
    bit<8>    op;      // 1 = request (client→server), 2 = reply (server→client)
    bit<8>    htype;   // hardware type (1 = Ethernet)
    bit<8>    hlen;    // hardware address length (6 for MAC)
    bit<8>    hops;    // relay agent hop count (0 if no relay)
    bit<32>   xid;     // transaction ID — client picks randomly, server echoes it back
    bit<16>   secs;    // seconds since client started the DHCP process
    bit<16>   flags;   // bit 15: broadcast flag (1 = client wants broadcast reply)
    bit<32>   ciaddr;  // client IP (0.0.0.0 if not yet assigned)
    bit<32>   yiaddr;  // "your" IP — the IP the server is offering to the client
    bit<32>   siaddr;  // server IP
    bit<32>   giaddr;  // relay agent IP (0 if no relay)
    bit<128>  chaddr;  // client hardware address (6-byte MAC + 10 bytes padding)
    bit<512>  sname;   // server hostname (64 bytes, usually zero-filled)
    bit<1024> file;    // boot filename (128 bytes, usually zero-filled)
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}