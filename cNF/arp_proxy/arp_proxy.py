#!/usr/bin/env python3
# SPDX-License-Identifier: ANCL-1.0
# Copyright (c) 2026  jfpereira <d12267@di.uminho.pt> — di.uminho.pt
# Academic use only · no commercial use · see LICENSE
# AI-assisted development: Claude (Anthropic)

import threading
import time
import yaml
from scapy.all import ARP, Ether, sendp, sniff
from cnf_api import CnfApi

REST_PORT = 8081

_lock = threading.Lock()
_state = {
    'interface': '',
    'table': {},            # ip -> mac
    'requests': 0,
    'total_response_ms': 0.0,
}


def load_config(path):
    with open(path) as f:
        return yaml.safe_load(f)


def _apply_config(config):
    with _lock:
        if 'interface' in config:
            _state['interface'] = config['interface']
        if 'entries' in config:
            _state['table'] = {e['ip']: e['mac'] for e in config['entries']}

def get_telemetry():
    with _lock:
        reqs     = _state['requests']
        total_ms = _state['total_response_ms']
    avg_ms = round(total_ms / reqs, 3) if reqs > 0 else 0.0
    return {'requests': reqs, 'avg_response_ms': avg_ms}


def get_config():
    with _lock:
        return {
            'interface': _state['interface'],
            'entries': [{'ip': ip, 'mac': mac}
                        for ip, mac in _state['table'].items()],
        }


def set_config(data):
    unknown = set(data.keys()) - {'interface', 'entries'}
    if unknown:
        return f'unknown fields: {unknown}'
    _apply_config(data)
    return None

def handle_arp_request(packet):
    if packet[ARP].op != 1:
        return

    target_ip = packet[ARP].pdst
    with _lock:
        reply_mac = _state['table'].get(target_ip)
        interface = _state['interface']

    if reply_mac is None:
        return

    t_start = time.monotonic()
    arp_reply = (
        Ether(dst=packet[Ether].src, src=reply_mac)
        / ARP(
            op=2,
            hwsrc=reply_mac,
            psrc=target_ip,
            hwdst=packet[ARP].hwsrc,
            pdst=packet[ARP].psrc,
        )
    )
    sendp(arp_reply, iface=interface, verbose=False)
    elapsed_ms = (time.monotonic() - t_start) * 1000

    with _lock:
        _state['requests'] += 1
        _state['total_response_ms'] += elapsed_ms

    print(f"ARP reply: {target_ip} is at {reply_mac} -> {packet[ARP].psrc}")


def main():
    config = load_config('arp_proxy.yaml')
    _apply_config(config)

    with _lock:
        iface = _state['interface']
        table = dict(_state['table'])

    print(f"ARP proxy listening on {iface}")
    print(f"Serving: {table}")
    print(f"REST API on :{REST_PORT}")

    CnfApi('arp_proxy', REST_PORT, get_telemetry, get_config, set_config).start()

    sniff(
        iface=iface,
        filter='arp',
        prn=handle_arp_request,
        store=False,
    )


if __name__ == '__main__':
    main()
