#!/usr/bin/env python3
# SPDX-License-Identifier: ANCL-1.0
# Copyright (c) 2026  jfpereira <d12267@di.uminho.pt> — di.uminho.pt
# Academic use only · no commercial use · see LICENSE
# AI-assisted development: Claude (Anthropic)

import logging
import os
import queue
import sys
import threading

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__))))

import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections
from plugin_base import PluginBase


class Controller:
    """
    Single network controller that manages all P4Runtime devices.

    The Controller is the only entity that speaks gRPC / P4Runtime.
    Plugins receive a Controller instance and call its methods — they
    never import p4runtime_lib directly.

    Threading model (Lab 3+):
      - Read thread (1/device): reads gRPC stream, pushes events to _event_queue
      - Main thread: after ctrl.run(), routes events from _event_queue to plugin queues
      - Plugin thread (1/plugin): pops from its queue, calls registered handlers
      - _write_lock serialises all gRPC writes (safe from any thread)
    """

    def __init__(self, log_dir='logs'):
        # name -> {'sw': Bmv2SwitchConnection, 'p4info_helper': P4InfoHelper, 'json_path': str}
        self.devices = {}
        # event_type -> [(plugin_name, callback, filter), ...]
        self._handlers = {}
        self._handlers_lock = threading.Lock()  # protects _handlers reads and writes
        # plugin_name -> Queue
        self._plugin_queues = {}
        self._write_lock = threading.Lock()     # serialises all gRPC write operations
        self._event_queue = queue.Queue()
        self.log_dir = log_dir
        self.logger = logging.getLogger('controller')

    # ── Connection & pipeline ─────────────────────────────────────────────────

    def connect(self, name, grpc_addr, device_id, p4info_path, json_path):
        """Open a P4Runtime session to a device and acquire mastership."""
        p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_path)

        sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=name,
            address=grpc_addr,
            device_id=device_id,
            proto_dump_file=os.path.join(self.log_dir, f"{name}-p4runtime-request.txt")
        )

        sw.MasterArbitrationUpdate()

        self.devices[name] = {
            'sw': sw,
            'p4info_helper': p4info_helper,
            'json_path': json_path
        }
        self.logger.info("connected %s (%s)", name, grpc_addr)

    def push_pipeline(self, device_name):
        """Push the compiled P4 program onto the device."""
        device = self.devices[device_name]
        sw = device['sw']
        p4info_helper = device['p4info_helper']
        json_path = device['json_path']

        sw.SetForwardingPipelineConfig(
            p4info=p4info_helper.p4info,
            bmv2_json_file_path=json_path
        )
        self.logger.info("pipeline pushed to %s", device_name)

    # ── Write operations ──────────────────────────────────────────────────────

    def install_multicast_group(self, device_name, group_id, replicas):
        """Install a PRE multicast group (used for flooding / broadcast)."""
        with self._write_lock:
            device = self.devices[device_name]
            mc_entry = device['p4info_helper'].buildMulticastGroupEntry(group_id, replicas)
            device['sw'].WritePREEntry(mc_entry)
        self.logger.info("%s multicast group %s installed", device_name, group_id)

    def install_clone_session(self, device_name, session_id, replicas):
        """Install a PRE clone session (used for packet mirroring / CPU copy)."""
        with self._write_lock:
            device = self.devices[device_name]
            clone_entry = device['p4info_helper'].buildCloneSessionEntry(session_id, replicas)
            device['sw'].WritePREEntry(clone_entry)
        self.logger.info("%s clone session %s installed", device_name, session_id)

    def install_table_entry(self, device_name, table_name, match_fields,
                            action_name, action_params=None):
        """Install one forwarding rule in a match-action table."""
        with self._write_lock:
            device = self.devices[device_name]
            table_entry = device['p4info_helper'].buildTableEntry(
                table_name=table_name,
                match_fields=match_fields,
                default_action=match_fields is None,
                action_name=action_name,
                action_params=action_params
            )
            device['sw'].WriteTableEntry(table_entry)
        self.logger.info("%s rule installed: %s", device_name, table_name)

    # ── Read operations ───────────────────────────────────────────────────────

    def read_table_entries(self, device_name, table_id=None):
        """Yield all entries currently installed in a device's table."""
        sw = self.devices[device_name]['sw']
        yield from sw.ReadTableEntries(table_id)

    def read_counters(self, device_name, counter_name, index=0):
        """Read a counter entry by name and index.

        Args:
            device_name  — registered device name (e.g. 'd2')
            counter_name — counter name as declared in the P4 program
            index        — counter array index (default 0)

        Returns:
            dict with keys 'packets' and 'bytes'
        """
        device = self.devices[device_name]
        counter_id = device['p4info_helper'].get_id('counters', counter_name)
        packets = 0
        bytes_count = 0
        for response in device['sw'].ReadCounters(counter_id, index):
            for entity in response.entities:
                packets     += entity.counter_entry.data.packet_count
                bytes_count += entity.counter_entry.data.byte_count
        return {'packets': packets, 'bytes': bytes_count}

    # ── Event system ──────────────────────────────────────────────────────────

    def subscribe(self, event_type, callback, plugin_name, filter=None):
        """
        Register a callback for an event type.

        Args:
            event_type  — must be a constant from PluginBase (e.g. PluginBase.PACKET_IN)
            callback    — callable(payload) invoked in the plugin's own thread
            plugin_name — name from plugin.info()['name']; used for routing
            filter      — optional callable(payload) → bool; the dispatcher calls
                          this before queuing the event. If it returns False the
                          plugin thread is never woken. Use this to match on packet
                          EtherType or any other payload field.

        Raises:
            ValueError if event_type is not in PluginBase.EVENTS.
        """
        if event_type not in PluginBase.EVENTS:
            raise ValueError(
                f"unknown event '{event_type}'. "
                f"Use a constant from PluginBase: {sorted(PluginBase.EVENTS)}"
            )
        with self._handlers_lock:
            self._handlers.setdefault(event_type, []).append((plugin_name, callback, filter))

    def emit(self, event_type, payload):
        """
        Publish an event to all subscribed plugins.

        May be called from any thread (plugin callbacks, startup code, …).
        The main dispatcher routes the event to each interested plugin's queue.

        Args:
            event_type — must be a constant from PluginBase (e.g. PluginBase.MAC_LEARNED)
            payload    — dict passed as-is to every registered handler

        Raises:
            ValueError if event_type is not in PluginBase.EVENTS.
        """
        if event_type not in PluginBase.EVENTS:
            raise ValueError(
                f"unknown event '{event_type}'. "
                f"Use a constant from PluginBase: {sorted(PluginBase.EVENTS)}"
            )
        self._event_queue.put((event_type, payload))

    def register_plugin(self, name):
        """Create a per-plugin event queue. Call before plugin.startup()."""
        self._plugin_queues[name] = queue.Queue()

    # ── Internal threads ──────────────────────────────────────────────────────

    def _read_loop(self, device_name):
        """Daemon thread: reads gRPC stream and pushes events to _event_queue."""
        sw = self.devices[device_name]['sw']
        try:
            for msg in sw.stream_msg_resp:
                update = msg.WhichOneof('update')
                if update == 'packet':
                    self._event_queue.put(('packet_in', {
                        'device': device_name,
                        'packet': msg.packet
                    }))
                elif update == 'digest':
                    self._event_queue.put(('digest', {
                        'device': device_name,
                        'digest': msg.digest
                    }))
                # 'arbitration' silently ignored
        except Exception as e:
            self.logger.warning("stream ended for %s: %s", device_name, e)

    def _plugin_loop(self, plugin_name, q):
        """Plugin thread: pops (handler, payload) from queue and calls handler."""
        while True:
            item = q.get()
            if item is None:
                break
            handler, payload = item
            try:
                handler(payload)
            except Exception as e:
                self.logger.error("[%s] handler error: %s", plugin_name, e)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def run(self):
        """
        Start the controller event loop.

        Launches one read thread per connected device and one plugin thread
        per registered plugin, then the main thread becomes the event dispatcher.
        Blocks until Ctrl+C.
        """
        for name in self.devices:
            threading.Thread(
                target=self._read_loop, args=(name,), daemon=True
            ).start()

        for name, q in self._plugin_queues.items():
            threading.Thread(
                target=self._plugin_loop, args=(name, q), daemon=True
            ).start()

        self.logger.info("running — press Ctrl+C to stop")
        try:
            while True:
                event = self._event_queue.get()
                if event is None:
                    break
                event_type, payload = event
                with self._handlers_lock:
                    handlers = list(self._handlers.get(event_type, []))
                for plugin_name, handler, handler_filter in handlers:
                    if handler_filter is None or handler_filter(payload):
                        self._plugin_queues[plugin_name].put((handler, payload))
        except KeyboardInterrupt:
            pass
        finally:
            for q in self._plugin_queues.values():
                q.put(None)  # sentinel: stop plugin thread

    def shutdown(self):
        """Close all switch connections cleanly."""
        ShutdownAllSwitchConnections()
        self.logger.info("shut down")
