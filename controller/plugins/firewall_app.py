#!/usr/bin/env python3
# SPDX-License-Identifier: ANCL-1.0
# Copyright (c) 2026  jfpereira <d12267@di.uminho.pt> — di.uminho.pt
# Academic use only · no commercial use · see LICENSE
# AI-assisted development: Claude (Anthropic)
"""
firewall_app.py — Lab 4 class exercise plugin.

Connects to d2, pushes the stateful firewall pipeline, installs forwarding
rules from d2_firewall.yaml, and polls the firewall counters every
POLL_INTERVAL seconds.
"""

import os
import threading

import grpc
import yaml

from plugin_base import PluginBase

POLL_INTERVAL = 5   # seconds between counter reads


class FirewallApp(PluginBase):

    def info(self):
        return {
            'name': 'firewall_app',
            'description': 'Manages the d2 stateful firewall and polls forwarded/dropped counters.'
        }

    def startup(self, ctrl, build_dir, config_dir):
        self._ctrl = ctrl
        self._stop_event = threading.Event()

        config_path = os.path.join(config_dir, 'd2_firewall.yaml')
        with open(config_path) as f:
            config = yaml.safe_load(f)

        self._device_name = config['device']

        try:
            ctrl.connect(
                name=self._device_name,
                grpc_addr=config['grpc_addr'],
                device_id=config['device_id'],
                p4info_path=os.path.join(build_dir, config['p4info']),
                json_path=os.path.join(build_dir, config['json'])
            )
            ctrl.push_pipeline(self._device_name)

            for entry in config.get('table_entries', []):
                ctrl.install_table_entry(
                    device_name=self._device_name,
                    table_name=entry['table'],
                    match_fields=entry.get('match'),
                    action_name=entry['action'],
                    action_params=entry.get('params')
                )
        except grpc.RpcError as e:
            self.logger.error("gRPC error on %s: %s %s",
                              self._device_name, e.code(), e.details())
            return

        threading.Thread(target=self._poll_counters, daemon=True).start()

    def _poll_counters(self):
        """Background thread: reads firewall counters and logs them periodically."""
        while not self._stop_event.is_set():
            try:
                forwarded = self._ctrl.read_counters(
                    self._device_name, 'MyIngress.forwardedCounter'
                )
                dropped = self._ctrl.read_counters(
                    self._device_name, 'MyIngress.droppedCounter'
                )
                self.logger.info(
                    "%s — forwarded: %d pkts / %d bytes | dropped: %d pkts / %d bytes",
                    self._device_name,
                    forwarded['packets'], forwarded['bytes'],
                    dropped['packets'],   dropped['bytes']
                )
            except Exception as e:
                self.logger.warning("counter read failed: %s", e)
            self._stop_event.wait(POLL_INTERVAL)

    def shutdown(self):
        self._stop_event.set()


plugin = FirewallApp
