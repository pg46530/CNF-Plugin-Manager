#!/usr/bin/env python3
# SPDX-License-Identifier: ANCL-1.0
# Copyright (c) 2026  jfpereira <d12267@di.uminho.pt> — di.uminho.pt
# Academic use only · no commercial use · see LICENSE
# AI-assisted development: Claude (Anthropic)

import yaml
import ipaddress
import threading
import time
from scapy.all import BOOTP, DHCP, Ether, IP, UDP, sendp, sniff

# DHCP PROTOCOL NOTES
# -------------------
# The DHCP exchange follows a four-step handshake:
#   1. Discover  — client broadcasts: "I need an IP" (client has no IP yet)
#   2. Offer     — server replies with an available IP
#   3. Request   — client broadcasts: "I accept that IP" (broadcast so other servers hear it)
#   4. Ack       — server confirms the assignment
#
# Broadcast vs unicast:
#   - Discover and Request are always sent by the client in broadcast (Ethernet + IP)
#     because the client has no IP address yet and cannot receive unicast IP packets.
#   - Offer and initial Ack are sent by the server in broadcast for the same reason.
#   - Renewal Ack (client already has an IP, sends Request with ciaddr set) can be
#     sent unicast directly to the client.
#   - NAK is always broadcast — the client's IP may be wrong or absent.
#
# Common pitfalls:
#   - Race condition: if two clients send Discover before any Ack is processed,
#     get_next_ip() returns the same IP to both. Reserve the IP at Offer time, not Ack time.
#   - INIT-REBOOT: dhclient caches leases and may skip Discover on restart, sending
#     a Request directly for a previously assigned IP. The server must handle this
#     gracefully — Ack if the IP is still available, NAK otherwise.
#   - Offer mismatch: the IP in the Request is chosen by the client, not the server.
#     A client could request an IP different from what was offered. Always validate
#     that the requested IP matches your offer before sending an Ack.
#   - Stale offers: if a client never sends a Request after receiving an Offer, the
#     offered IP is blocked forever unless offers have a timeout.


def load_config(path):
    with open(path) as f:
        config = yaml.safe_load(f)
    return config


def build_pool(config):
    """Build the IP pool for the full subnet.
    Each entry: {mac, reserved}
    generate all IPs in the subnet from config["subnet"] and config["subnet_mask"]
    mark as reserved: network address, broadcast, server_ip, gateway
    """
    subnet = config["subnet"]
    subnet_mask = config["subnet_mask"]
    server_ip = config["server_ip"]
    gateway = config["gateway"]
    subnet = ipaddress.ip_network(f"{subnet}/{subnet_mask}", strict=False)
    
    # Generate all usable IPs
    available_ips = [str(ip) for ip in subnet.hosts()]
    
    # Mark reserved IPs
    reserved_ips = {
        str(subnet.network_address),    # .0
        str(subnet.broadcast_address),  # .255
        server_ip,                  # Server IP
        gateway,                    # Gateway
    }
    
    # Remove reserved from available pool
    available_ips = [ip for ip in available_ips if ip not in reserved_ips]
    
    # Apply static reservations from YAML
    static_reservations = {}
    if config.get("reservations"):
        for reservation in config["reservations"]:
            ip = reservation.get("ip")
            mac = reservation.get("mac")
            if ip and mac:
                if ip in available_ips:
                    available_ips.remove(ip)
                static_reservations[mac] = ip
    
    pool = {
        "available": available_ips,
        "reserved": reserved_ips,
        "static_reservations": static_reservations,
        "leases": {},              
        "lock": threading.Lock(),  # Thread safety
    }
    
    return pool


def get_next_ip(pool, offered_pool):
    """Return the next available IP from the pool, or None if exhausted."""
    with pool["lock"]:
        # Collect all taken IPs
        taken_ips = set(pool["reserved"])
        for mac, offer_data in offered_pool.items():
            taken_ips.add(offer_data["ip"])
        for mac, lease_data in pool["leases"].items():
            taken_ips.add(lease_data["ip"])
        
        # Find first available
        for ip in pool["available"]:
            if ip not in taken_ips:
                return ip
        
        return None


def handle_dhcp(packet, interface, config, pool, offered_pool):
    """handle DHCP Discover and Request messages"""
    try:
        if not packet.haslayer(BOOTP):
            return
        
        bootp = packet[BOOTP]
        dhcp_layer = packet[DHCP]
        
        # Extract message type
        msg_type = None
        for option in dhcp_layer.options:
            if option[0] == "message-type":
                msg_type = option[1]
                break
        
        if msg_type is None:
            return
        
        # Extract client MAC
        client_mac = bootp.chaddr[:6].hex()
        client_mac = ':'.join([client_mac[i:i+2] for i in range(0, len(client_mac), 2)])
        
        # DISCOVER: send OFFER
        if msg_type == 1:
            # Check static reservation
            if client_mac in pool["static_reservations"]:
                offer_ip = pool["static_reservations"][client_mac]
            else:
                offer_ip = get_next_ip(pool, offered_pool)
            
            if offer_ip is None:
                print(f"[DHCP] No available IPs for {client_mac}")
                return
            
            # Record offer
            offered_pool[client_mac] = {
                "ip": offer_ip,
                "timestamp": time.time()
            }
            
            print(f"[DHCP OFFER] {client_mac} -> {offer_ip}")
            
            # Build OFFER response
            subnet_mask = config["subnet_mask"]
            gateway = config["gateway"]
            dns = config["dns"]
            
            resp = Ether(dst=packet.src) / IP(dst="255.255.255.255") / UDP(sport=67, dport=68)
            resp /= BOOTP(
                op=2,
                yiaddr=offer_ip,
                siaddr=config["server_ip"],
                giaddr=packet[IP].dst if packet.haslayer(IP) else "0.0.0.0",
                chaddr=bootp.chaddr,
                xid=bootp.xid
            )
            resp /= DHCP(options=[
                ("message-type", 2),
                ("subnet_mask", subnet_mask),
                ("router", gateway),
                ("name_server", dns),
                ("lease_time", config["lease_time"]),
                ("server_id", config["server_ip"]),
                "end"
            ])
            sendp(resp, iface=interface, verbose=False)
        
        # REQUEST: send ACK 
        elif msg_type == 3:
            requested_ip = None
            
            # Extract requested IP from options
            for option in dhcp_layer.options:
                if option[0] == "requested_addr":
                    requested_ip = option[1]
                    break
            
            # If no requested_addr, use ciaddr
            if requested_ip is None:
                requested_ip = bootp.ciaddr if bootp.ciaddr and bootp.ciaddr != "0.0.0.0" else None
            
            # Validate requested IP
            valid = False
            if requested_ip and requested_ip not in pool["reserved"]:
                # Check if offered to this client
                if client_mac in offered_pool and offered_pool[client_mac]["ip"] == requested_ip:
                    valid = True
                elif client_mac in pool["static_reservations"] and pool["static_reservations"][client_mac] == requested_ip:
                    valid = True
                elif client_mac in pool["leases"] and pool["leases"][client_mac]["ip"] == requested_ip:
                    # Renewal
                    valid = True
            
            if valid:
                # Send ACK
                with pool["lock"]:
                    pool["leases"][client_mac] = {
                        "ip": requested_ip,
                        "expiry": time.time() + config["lease_time"]
                    }
                
                # Remove from offered pool
                if client_mac in offered_pool:
                    del offered_pool[client_mac]
                
                print(f"[DHCP ACK] {client_mac} -> {requested_ip}")
                
                subnet_mask = config["subnet_mask"]
                gateway = config["gateway"]
                dns = config["dns"]
                
                resp = Ether(dst=packet.src) / IP(dst="255.255.255.255") / UDP(sport=67, dport=68)
                resp /= BOOTP(
                    op=2,
                    yiaddr=requested_ip,
                    siaddr=config["server_ip"],
                    giaddr=packet[IP].dst if packet.haslayer(IP) else "0.0.0.0",
                    chaddr=bootp.chaddr,
                    xid=bootp.xid
                )
                resp /= DHCP(options=[
                    ("message-type", 5),
                    ("subnet_mask", subnet_mask),
                    ("router", gateway),
                    ("name_server", dns),
                    ("lease_time", config["lease_time"]),
                    ("server_id", config["server_ip"]),
                    "end"
                ])
                sendp(resp, iface=interface, verbose=False)
            else:
                # Send NAK
                print(f"[DHCP NAK] {client_mac} (requested {requested_ip})")
                
                resp = Ether(dst=packet.src) / IP(dst="255.255.255.255") / UDP(sport=67, dport=68)
                resp /= BOOTP(
                    op=2,
                    chaddr=bootp.chaddr,
                    xid=bootp.xid
                )
                resp /= DHCP(options=[
                    ("message-type", 6),
                    ("server_id", config["server_ip"]),
                    "end"
                ])
                sendp(resp, iface=interface, verbose=False)
    
    except Exception as e:
        print(f"[ERROR] {e}")


def main():
    config       = load_config("dhcp_server.yaml")
    interface    = config["interface"]
    pool         = build_pool(config)
    offered_pool = {}  # {mac -> {ip, timestamp}} — pending offers not yet Acked

    print(f"DHCP server listening on {interface}")

    sniff(
        iface=interface,
        filter="udp and (port 67 or port 68)",
        prn=lambda pkt: handle_dhcp(pkt, interface, config, pool, offered_pool),
        store=False,
    )


if __name__ == "__main__":
    main()
