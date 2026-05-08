#!/usr/bin/env python3
# SPDX-License-Identifier: ANCL-1.0
# Copyright (c) 2026  jfpereira <d12267@di.uminho.pt> — di.uminho.pt
# Academic use only · no commercial use · see LICENSE
# AI-assisted development: Claude (Anthropic)

import yaml
from scapy.all import ARP, Ether, sendp, sniff


def load_config(path):
    with open(path) as f:
        config = yaml.safe_load(f)
    interface = config["interface"]
    table = {entry["ip"]: entry["mac"] for entry in config["entries"]}
    return interface, table


def handle_arp_request(packet, interface, table):
    # only handle ARP requests (op=1)
    if packet[ARP].op != 1:
        return

    target_ip = packet[ARP].pdst
    if target_ip not in table:
        return

    reply_mac = table[target_ip]

    arp_reply = (
        Ether(dst=packet[Ether].src, src=reply_mac)
        / ARP(
            op=2,                       # ARP reply
            hwsrc=reply_mac,            # sender MAC  = gateway MAC
            psrc=target_ip,             # sender IP   = gateway IP
            hwdst=packet[ARP].hwsrc,    # target MAC  = requester MAC
            pdst=packet[ARP].psrc,      # target IP   = requester IP
        )
    )

    sendp(arp_reply, iface=interface, verbose=False)
    print(f"ARP reply: {target_ip} is at {reply_mac} -> {packet[ARP].psrc}")


def main():
    interface, table = load_config("arp_proxy.yaml")
    print(f"ARP proxy listening on {interface}")
    print(f"Serving: {table}")

    sniff(
        iface=interface,
        filter="arp",
        prn=lambda pkt: handle_arp_request(pkt, interface, table),
        store=False,
    )


if __name__ == "__main__":
    main()
