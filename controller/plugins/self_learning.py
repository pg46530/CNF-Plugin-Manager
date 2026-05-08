#!/usr/bin/env python3
# SPDX-License-Identifier: ANCL-1.0
# Copyright (c) 2026  jfpereira <d12267@di.uminho.pt> — di.uminho.pt
# Academic use only · no commercial use · see LICENSE
# AI-assisted development: Claude (Anthropic)
"""
self_learning.py — Lab 3 plugin: self-learning L2 switch.

Connects to d1 and d3 (l2switch.p4), installs a broadcast multicast group
and a CPU clone session on each device, then subscribes to packet_in events.

When a packet arrives at the controller, on_packet_in extracts the source MAC
and ingress port, installs a unicast forwarding rule for that MAC, and emits a
'mac_learned' event so other plugins can react.

Inherits from PluginBase and overrides on_packet_in.
"""

import os

import grpc

from plugin_base import PluginBase

# Devices managed by this plugin (L2 switches only — d2 is an L3 router)
L2_DEVICES = [
    {
        'name': 'd1',
        'grpc_addr': '127.0.0.1:50051',
        'device_id': 1,
        'p4info': 'l2switch.p4info.txt',
        'json': 'l2switch.json',
    },
    {
        'name': 'd3',
        'grpc_addr': '127.0.0.1:50053',
        'device_id': 3,
        'p4info': 'l2switch.p4info.txt',
        'json': 'l2switch.json',
    },
]

# Ports connected to hosts (and uplink); all included in the broadcast group
MULTICAST_REPLICAS = [
    {'egress_port': 1, 'instance': 1},
    {'egress_port': 2, 'instance': 1},
    {'egress_port': 3, 'instance': 1},
    {'egress_port': 4, 'instance': 1},
]

# CPU port — clone session sends a copy of each packet to the controller
CPU_PORT = 510

# EtherType used by l2switch.p4 to mark packets cloned to the CPU.
# Must match the P4 constant: const bit<16> L2_LEARN_ETHER_TYPE = 0x1234
L2_LEARN_ETHER_TYPE = b'\x12\x34'


class SelfLearning(PluginBase):

    def info(self):
        return {
            'name': 'self_learning',
            'description': 'Self-learning L2 switch: learns MACs from packet_in events.'
        }

    def startup(self, ctrl, build_dir, config_dir):
        """
        Connect to d1 and d3, push the pipeline, install the broadcast
        multicast group and CPU clone session, then subscribe to packet_in.

        Must return promptly — no loops here.
        """
        self._ctrl = ctrl
        # Per-device set of already-learned MACs — prevents duplicate rule installs
        self._learned = {dev['name']: set() for dev in L2_DEVICES}

        for dev in L2_DEVICES:
            try:
                ctrl.connect(
                    name=dev['name'],
                    grpc_addr=dev['grpc_addr'],
                    device_id=dev['device_id'],
                    p4info_path=os.path.join(build_dir, dev['p4info']),
                    json_path=os.path.join(build_dir, dev['json'])
                )
                ctrl.push_pipeline(dev['name'])

                # Broadcast group: used by l2switch.p4 when destination is unknown
                ctrl.install_multicast_group(
                    device_name=dev['name'],
                    group_id=1,
                    replicas=MULTICAST_REPLICAS
                )

                # Clone session: l2switch.p4 clones every packet to the CPU port
                # so the controller can learn source MACs
                ctrl.install_clone_session(
                    device_name=dev['name'],
                    session_id=100,  # must match clone_preserving_field_list(..., 100, ...) in P4
                    replicas=[{'egress_port': CPU_PORT, 'instance': 1}]
                )

            except grpc.RpcError as e:
                self.logger.error("gRPC error on %s: %s %s",
                                  dev['name'], e.code(), e.details())

        ctrl.subscribe(
            PluginBase.PACKET_IN,
            self.on_packet_in,
            self.info()['name'],
            filter=lambda e: e['packet'].payload[12:14] == L2_LEARN_ETHER_TYPE
        )
        ctrl.subscribe(PluginBase.STATE_RESET,   self.on_state_reset,   self.info()['name'])
        ctrl.subscribe(PluginBase.ENTRY_REMOVED, self.on_entry_removed, self.info()['name'])

    def on_packet_in(self, event):
        """
        Override of PluginBase.on_packet_in.

        Extracts the ingress port from packet metadata and the source MAC from
        the Ethernet header. On first sight of a MAC, installs a unicast
        forwarding rule so future frames are not flooded. Emits 'mac_learned'
        so other plugins can react.
        """
        device_name = event['device']
        payload = event['packet'].payload

        # CPU packet layout (22 bytes total):
        #   bytes  0– 5  ethernet.dstAddr
        #   bytes  6–11  ethernet.srcAddr
        #   bytes 12–13  ethernet.etherType  (0x1234 — already checked by filter)
        #   bytes 14–19  cpu.srcAddr         ← MAC to learn
        #   bytes 20–21  cpu.ingress_port    ← big-endian 16-bit port number
        src_mac      = ':'.join(f'{b:02x}' for b in payload[14:20])
        ingress_port = int.from_bytes(payload[20:22], 'big')

        self.logger.info("packet_in | device=%s port=%s src_mac=%s",
                         device_name, ingress_port, src_mac)

        # Notify other plugins that a new MAC has been observed on this port
        self._ctrl.emit(PluginBase.MAC_LEARNED, {
            'device': device_name,
            'mac': src_mac,
            'port': ingress_port
        })

        # Install forwarding rules on first sight of this MAC.
        # The guard prevents a duplicate-entry gRPC error if the same src_mac
        # arrives again before the sMacLookup rule takes effect on the switch.
        if src_mac not in self._learned[device_name]:
            try:
                # sMacLookup hit → NoAction: suppresses future clones for this source
                self._ctrl.install_table_entry(
                    device_name=device_name,
                    table_name='MyIngress.sMacLookup',
                    match_fields={'hdr.eth.srcAddr': src_mac},
                    action_name='NoAction'
                )
                # dMacLookup hit → forward: delivers frames destined for this MAC
                self._ctrl.install_table_entry(
                    device_name=device_name,
                    table_name='MyIngress.dMacLookup',
                    match_fields={'hdr.eth.dstAddr': src_mac},
                    action_name='MyIngress.forward',
                    action_params={'egress_port': ingress_port}
                )
                self._learned[device_name].add(src_mac)
            except grpc.RpcError as e:
                if e.code() == grpc.StatusCode.ALREADY_EXISTS:
                    # Rule already on the switch (e.g. installed by another path)
                    # — re-cache it so we don't keep retrying
                    self._learned[device_name].add(src_mac)
                else:
                    self.logger.error("install failed for %s: %s", src_mac, e.details())


    def on_state_reset(self, event):
        """All tables on a device were wiped — forget every learned MAC for it."""
        device_name = event['device']
        if device_name in self._learned:
            count = len(self._learned[device_name])
            self._learned[device_name].clear()
            self.logger.info("state reset on %s — cleared %d learned MACs",
                             device_name, count)

    def on_entry_removed(self, event):
        """A single forwarding rule disappeared — forget just that MAC."""
        device_name = event['device']
        match_key   = event['match_key']
        src_mac = ':'.join(f'{b:02x}' for b in match_key)
        if src_mac in self._learned.get(device_name, set()):
            self._learned[device_name].discard(src_mac)
            self.logger.info("entry removed on %s — forgot %s", device_name, src_mac)


plugin = SelfLearning
