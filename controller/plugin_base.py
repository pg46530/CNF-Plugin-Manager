#!/usr/bin/env python3
# SPDX-License-Identifier: ANCL-1.0
# Copyright (c) 2026  jfpereira <d12267@di.uminho.pt> — di.uminho.pt
# Academic use only · no commercial use · see LICENSE
# AI-assisted development: Claude (Anthropic)
"""
plugin_base.py — Abstract base class for all controller plugins.

Every plugin must:
  1. Live in controller/plugins/<name>.py
  2. Define a class that inherits from PluginBase
  3. Implement info() and startup()
  4. Expose a module-level name: plugin = MyPlugin

Plugin lifecycle
----------------
startup(ctrl, build_dir, config_dir)
    Called once by the runner before ctrl.run().
    Must return promptly — no loops, no blocking calls, no time.sleep().
    Allowed: ctrl.connect(), ctrl.push_pipeline(), ctrl.install_*(),
             ctrl.subscribe(event, fn, name), ctrl.emit(event, payload).

Event callbacks (e.g. on_packet_in)
    Invoked by the plugin's own thread inside ctrl.run().
    May call ctrl.install_table_entry() and other write methods safely
    (the controller serialises writes with a lock).
    May call ctrl.emit() to publish custom events to other plugins.

shutdown()
    Called after Ctrl+C, before the process exits.
    Override to release resources. Default is a no-op.

Inter-plugin communication
--------------------------
Plugins never reference each other directly.
All communication goes through the controller event bus:

    # Plugin A — publisher (inside a callback)
    ctrl.emit('mac_learned', {'device': device_name, 'mac': src_mac, 'port': port})

    # Plugin B — subscriber (inside startup)
    ctrl.subscribe('mac_learned', self.on_mac_learned, self.info()['name'])

Example skeleton
----------------
    from plugin_base import PluginBase

    class MyPlugin(PluginBase):

        def info(self):
            return {
                'name': 'my_plugin',
                'description': 'One-line description of what this plugin does.'
            }

        def startup(self, ctrl, build_dir, config_dir):
            self.logger.info("starting")
            # connect devices, install rules, subscribe to events …
            ctrl.subscribe('packet_in', self.on_packet_in, self.info()['name'])

        def on_packet_in(self, event):
            device_name = event['device']
            packet = event['packet']
            self.logger.info("packet_in from %s", device_name)

        def shutdown(self):
            pass  # release resources if needed

    plugin = MyPlugin   # runner discovers this name
"""

import logging
from abc import ABC, abstractmethod


class PluginBase(ABC):

    # ── Event registry ────────────────────────────────────────────────────────
    # Named constants for every event recognised by the framework.
    # Always use these — never pass raw strings to subscribe() or emit().
    # A typo on a constant raises AttributeError at startup; a typo on a raw
    # string silently misfires at runtime.
    PACKET_IN     = 'packet_in'     # gRPC stream: packet cloned to CPU by the data plane
    DIGEST        = 'digest'        # gRPC stream: digest message from the data plane
    MAC_LEARNED   = 'mac_learned'   # emitted by self_learning when a new src MAC is seen
    ENTRY_ADDED   = 'entry_added'   # a table entry appeared that was not there before
    ENTRY_REMOVED = 'entry_removed' # a single table entry disappeared from the switch
    STATE_RESET   = 'state_reset'   # all table entries on a device were wiped at once
    CNF_TELEMETRY = 'cnf_telemetry' # emitted by cnf_control after each telemetry poll
    CNF_CONFIG    = 'cnf_config'    # consumed by cnf_control to apply config to a CNF
    CNF_DOWN      = 'cnf_down'      # emitted by cnf_control when a CNF becomes unreachable
    CNF_UP        = 'cnf_up'        # emitted by cnf_control when a CNF recovers

    # Full set — used by the controller to reject unknown event names early.
    EVENTS = frozenset({PACKET_IN, DIGEST, MAC_LEARNED,
                        ENTRY_ADDED, ENTRY_REMOVED, STATE_RESET,
                        CNF_TELEMETRY, CNF_CONFIG, CNF_DOWN, CNF_UP})

    @property
    def logger(self):
        """Named logger for this plugin — use instead of print()."""
        if not hasattr(self, '_logger'):
            self._logger = logging.getLogger(self.info()['name'])
        return self._logger

    @abstractmethod
    def info(self):
        """
        Return a dict describing this plugin.

        Required keys:
            name        (str) — short identifier matching the filename, e.g. 'static_rule'
            description (str) — one-line description of what the plugin does
        """

    @abstractmethod
    def startup(self, ctrl, build_dir, config_dir):
        """
        Connect devices, push pipelines, install rules, and subscribe to events.

        Must return promptly. The controller event loop has not started yet —
        do not loop or block here.

        Args:
            ctrl       — Controller instance (owns the gRPC connections)
            build_dir  — path to compiled P4 artifacts (JSON + p4info)
            config_dir — path to YAML config/topology files
        """

    def shutdown(self):
        """Called on controller shutdown. Override to release resources."""
        pass

    # ── Default event handlers ────────────────────────────────────────────────
    # One no-op method per event in EVENTS.
    # Subclasses override only the events they care about.

    def on_packet_in(self, event):
        """Called when the data plane clones a packet to the CPU port."""
        pass

    def on_digest(self, event):
        """Called when the data plane sends a digest message."""
        pass

    def on_mac_learned(self, event):
        """Called when another plugin emits a 'mac_learned' event."""
        pass

    def on_entry_added(self, event):
        """Called when a table entry appears that was not in the previous snapshot."""
        pass

    def on_entry_removed(self, event):
        """Called when a single table entry disappears from the switch."""
        pass

    def on_state_reset(self, event):
        """Called when all table entries on a device are wiped at once."""
        pass
