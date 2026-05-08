#!/usr/bin/env python3
# SPDX-License-Identifier: ANCL-1.0
# Copyright (c) 2026  jfpereira <d12267@di.uminho.pt> — di.uminho.pt
# Academic use only · no commercial use · see LICENSE
# AI-assisted development: Claude (Anthropic)
"""
run_controller.py — Controller runner.

Single entry point for the control plane:
  1. Creates one Controller instance (owns all P4Runtime / gRPC connections)
  2. Loads each plugin passed via --plugins, registers it, calls startup()
  3. Starts the event loop with ctrl.run()

Every plugin must be a class that inherits from PluginBase and expose a
module-level name 'plugin'. See controller/plugin_base.py for the full interface.
"""

import argparse
import importlib
import logging
import os
import sys

# Ensure controller/ is on the path so that 'controller' and 'p4runtime_lib'
# are importable both from this runner and from any plugin it loads.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from controller import Controller

logging.basicConfig(level=logging.INFO, format='[%(name)s] %(message)s')
logger = logging.getLogger('runner')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller Runner')
    parser.add_argument('--buildDir',
                        help='Directory with compiled P4 artifacts',
                        type=str, action='store', default='build')
    parser.add_argument('--configDir',
                        help='Directory with YAML config files',
                        type=str, action='store', default='controller/resources')
    parser.add_argument('--plugins', nargs='+', required=True,
                        metavar='PLUGIN',
                        help='Plugin names to load from controller/plugins/')
    args = parser.parse_args()

    os.makedirs('logs', exist_ok=True)
    ctrl = Controller()
    loaded_plugins = []
    try:
        for plugin_name in args.plugins:
            mod = importlib.import_module(f'plugins.{plugin_name}')
            plugin = mod.plugin()
            info = plugin.info()
            logger.info("loading plugin '%s': %s", info['name'], info['description'])
            ctrl.register_plugin(info['name'])
            plugin.startup(ctrl, args.buildDir, args.configDir)
            loaded_plugins.append(plugin)
        ctrl.run()
    except KeyboardInterrupt:
        pass
    finally:
        for plugin in loaded_plugins:
            plugin.shutdown()
        ctrl.shutdown()
