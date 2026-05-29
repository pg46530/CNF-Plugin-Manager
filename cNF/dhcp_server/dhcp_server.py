#!/usr/bin/env python3
# SPDX-License-Identifier: ANCL-1.0
# Copyright (c) 2026  jfpereira <d12267@di.uminho.pt> — di.uminho.pt
# Academic use only · no commercial use · see LICENSE
# AI-assisted development: Claude (Anthropic)

import ipaddress
import threading
import time
import yaml
from scapy.all import BOOTP, DHCP, Ether, IP, UDP, sendp, sniff
from cnf_api import CnfApi

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

REST_PORT = 8080

_state = {
    'config':       {},   # full config dict loaded from YAML
    'pool':         {},   # built by build_pool()
    'offered_pool': {},   # mac -> {ip, timestamp}  (pending offers)
    'requests':     0,    # total DHCP messages handled
    'lock':         threading.Lock(),
}

def load_config(path):
    with open(path) as f:
        return yaml.safe_load(f)


def build_pool(config):
    """Build the IP pool for the full subnet.
    Each entry: {mac, reserved}
    generate all IPs in the subnet from config["subnet"] and config["subnet_mask"]
    mark as reserved: network address, broadcast, server_ip, gateway
    """
    subnet      = config['subnet']
    subnet_mask = config['subnet_mask']
    server_ip   = config['server_ip']
    gateway     = config['gateway']
    network     = ipaddress.ip_network(f'{subnet}/{subnet_mask}', strict=False)

    available_ips = [str(ip) for ip in network.hosts()]

    reserved_ips = {
        str(network.network_address),
        str(network.broadcast_address),
        server_ip,
        gateway,
    }

    available_ips = [ip for ip in available_ips if ip not in reserved_ips]

    static_reservations = {}
    if config.get('reservations'):
        for reservation in config['reservations']:
            ip  = reservation.get('ip')
            mac = reservation.get('mac')
            if ip and mac:
                if ip in available_ips:
                    available_ips.remove(ip)
                static_reservations[mac] = ip

    return {
        'available':           available_ips,
        'reserved':            reserved_ips,
        'static_reservations': static_reservations,
        'leases':              {},
        'lock':                threading.Lock(),
    }


def get_next_ip(pool, offered_pool):
    """Return the next available IP from the pool, or None if exhausted."""
    with pool['lock']:
        taken_ips = set(pool['reserved'])
        for offer_data in offered_pool.values():
            taken_ips.add(offer_data['ip'])
        for lease_data in pool['leases'].values():
            taken_ips.add(lease_data['ip'])
        for ip in pool['available']:
            if ip not in taken_ips:
                return ip
        return None

def get_telemetry():
    with _state['lock']:
        reqs = _state['requests']
        leases = dict(_state['pool'].get('leases', {}))
    leased_ips = [
        {'ip': data['ip'], 'mac': mac, 'expiry': data['expiry']}
        for mac, data in leases.items()
    ]
    return {
        'requests':   reqs,
        'leased_ips': len(leased_ips),
        'ips':        leased_ips,
    }


def get_config():
    with _state['lock']:
        cfg = _state['config']
        return {
            'subnet':      cfg.get('subnet'),
            'subnet_mask': cfg.get('subnet_mask'),
            'gateway':     cfg.get('gateway'),
            'dns':         cfg.get('dns'),
            'lease_time':  cfg.get('lease_time'),
        }


def set_config(data):
    allowed = {'gateway', 'dns', 'lease_time'}
    unknown = set(data.keys()) - allowed
    if unknown:
        return f'unknown or immutable fields: {unknown}'
    with _state['lock']:
        _state['config'].update(data)
    return None


# ---------------------------------------------------------------------------
# DHCP packet handler
# ---------------------------------------------------------------------------

def handle_dhcp(packet):
    """Handle DHCP Discover and Request messages."""
    try:
        if not packet.haslayer(BOOTP):
            return

        bootp     = packet[BOOTP]
        dhcp_layer = packet[DHCP]

        msg_type = None
        for option in dhcp_layer.options:
            if option[0] == 'message-type':
                msg_type = option[1]
                break

        if msg_type is None:
            return

        with _state['lock']:
            _state['requests'] += 1
            config       = _state['config']
            pool         = _state['pool']
            offered_pool = _state['offered_pool']

        client_mac = bootp.chaddr[:6].hex()
        client_mac = ':'.join([client_mac[i:i+2] for i in range(0, len(client_mac), 2)])

        interface = config['interface']

        # DISCOVER: send OFFER
        if msg_type == 1:
            if client_mac in pool['static_reservations']:
                offer_ip = pool['static_reservations'][client_mac]
            else:
                offer_ip = get_next_ip(pool, offered_pool)

            if offer_ip is None:
                print(f'[DHCP] No available IPs for {client_mac}')
                return

            offered_pool[client_mac] = {'ip': offer_ip, 'timestamp': time.time()}
            print(f'[DHCP OFFER] {client_mac} -> {offer_ip}')

            resp = Ether(dst=packet.src) / IP(dst='255.255.255.255') / UDP(sport=67, dport=68)
            resp /= BOOTP(
                op=2,
                yiaddr=offer_ip,
                siaddr=config['server_ip'],
                giaddr=packet[IP].dst if packet.haslayer(IP) else '0.0.0.0',
                chaddr=bootp.chaddr,
                xid=bootp.xid,
            )
            resp /= DHCP(options=[
                ('message-type', 2),
                ('subnet_mask',  config['subnet_mask']),
                ('router',       config['gateway']),
                ('name_server',  config['dns']),
                ('lease_time',   config['lease_time']),
                ('server_id',    config['server_ip']),
                'end',
            ])
            sendp(resp, iface=interface, verbose=False)

        # REQUEST: send ACK or NAK
        elif msg_type == 3:
            requested_ip = None
            for option in dhcp_layer.options:
                if option[0] == 'requested_addr':
                    requested_ip = option[1]
                    break
            if requested_ip is None:
                ciaddr = bootp.ciaddr
                if ciaddr and ciaddr != '0.0.0.0':
                    requested_ip = ciaddr

            valid = False
            if requested_ip and requested_ip not in pool['reserved']:
                if client_mac in offered_pool and offered_pool[client_mac]['ip'] == requested_ip:
                    valid = True
                elif client_mac in pool['static_reservations'] and pool['static_reservations'][client_mac] == requested_ip:
                    valid = True
                elif client_mac in pool['leases'] and pool['leases'][client_mac]['ip'] == requested_ip:
                    valid = True  # renewal

            if valid:
                with pool['lock']:
                    pool['leases'][client_mac] = {
                        'ip':     requested_ip,
                        'expiry': time.time() + config['lease_time'],
                    }
                if client_mac in offered_pool:
                    del offered_pool[client_mac]

                print(f'[DHCP ACK] {client_mac} -> {requested_ip}')
                resp = Ether(dst=packet.src) / IP(dst='255.255.255.255') / UDP(sport=67, dport=68)
                resp /= BOOTP(
                    op=2,
                    yiaddr=requested_ip,
                    siaddr=config['server_ip'],
                    giaddr=packet[IP].dst if packet.haslayer(IP) else '0.0.0.0',
                    chaddr=bootp.chaddr,
                    xid=bootp.xid,
                )
                resp /= DHCP(options=[
                    ('message-type', 5),
                    ('subnet_mask',  config['subnet_mask']),
                    ('router',       config['gateway']),
                    ('name_server',  config['dns']),
                    ('lease_time',   config['lease_time']),
                    ('server_id',    config['server_ip']),
                    'end',
                ])
                sendp(resp, iface=interface, verbose=False)
            else:
                print(f'[DHCP NAK] {client_mac} (requested {requested_ip})')
                resp = Ether(dst=packet.src) / IP(dst='255.255.255.255') / UDP(sport=67, dport=68)
                resp /= BOOTP(op=2, chaddr=bootp.chaddr, xid=bootp.xid)
                resp /= DHCP(options=[
                    ('message-type', 6),
                    ('server_id', config['server_ip']),
                    'end',
                ])
                sendp(resp, iface=interface, verbose=False)

    except Exception as e:
        print(f'[ERROR] {e}')


def main():
    config = load_config('dhcp_server.yaml')

    with _state['lock']:
        _state['config'] = config
        _state['pool']   = build_pool(config)

    interface = config['interface']
    print(f'DHCP server listening on {interface}')
    print(f'REST API on :{REST_PORT}')

    CnfApi('dhcp_server', REST_PORT, get_telemetry, get_config, set_config).start()

    sniff(
        iface=interface,
        filter='udp and (port 67 or port 68)',
        prn=handle_dhcp,
        store=False,
    )


if __name__ == '__main__':
    main()
