import json
import os
import threading
import urllib.error
import urllib.request

import yaml

from plugin_base import PluginBase


class CnfControl(PluginBase):

    def info(self):
        return {
            'name': 'cnf_control',
            'description': 'Polls telemetry from registered CNFs and forwards config updates.',
        }

    def startup(self, ctrl, build_dir, config_dir):
        self._ctrl = ctrl
        self._stop = threading.Event()
        self._down = {}  # tracks which CNFs are currently unreachable

        registry_path = os.path.join(config_dir, 'cnf_registry.yaml')
        with open(registry_path) as f:
            registry = yaml.safe_load(f)
        self._cnfs = registry.get('cnfs', [])
        self._poll_interval = registry.get('poll_interval', 10)
        dhcp = registry.get('dhcp_settings', {})
        self._pool_warn_threshold = dhcp.get('pool_warn_threshold', 200)
        self._lease_time_reduced  = dhcp.get('lease_time_reduced', 300)

        self.logger.info('registered CNFs: %s', [c['name'] for c in self._cnfs])

        # Subscribe to config-apply requests from other plugins
        ctrl.subscribe(PluginBase.CNF_CONFIG, self._on_cnf_config, self.info()['name'])
        # Case 1: correlate MAC -> IP when self_learning learns a new MAC
        ctrl.subscribe(PluginBase.MAC_LEARNED, self._on_mac_learned, self.info()['name'])

        # Start background polling thread
        self._poll_thread = threading.Thread(
            target=self._poll_loop,
            daemon=True,
            name='cnf-control-poll',
        )
        self._poll_thread.start()

    def _poll_loop(self):
        while not self._stop.wait(self._poll_interval):
            for cnf in self._cnfs:
                self._poll_cnf(cnf)

    def _poll_cnf(self, cnf):
        name = cnf['name']
        url  = cnf['url']

        # --- health check (Case 3) ---
        health = self._get_json(f'{url}/health')
        if health is None:
            if not self._down.get(name):
                self._down[name] = True
                self.logger.warning('[%s] UNREACHABLE', name)
                self._ctrl.emit(PluginBase.CNF_DOWN, {'cnf': name})
            return
        if self._down.get(name):
            self._down[name] = False
            self.logger.info('[%s] RECOVERED', name)
            self._ctrl.emit(PluginBase.CNF_UP, {'cnf': name})

        # --- telemetry ---
        data = self._get_json(f'{url}/telemetry')
        if data is None:
            return
        self.logger.info('[%s] telemetry: %s', name, data)
        self._ctrl.emit(PluginBase.CNF_TELEMETRY, {'cnf': name, 'data': data})

        # --- Case 2: pool pressure ---
        if name == 'dhcp_server':
            leased = data.get('leased_ips', 0)
            if leased >= self._pool_warn_threshold:
                self.logger.warning(
                    '[%s] pool pressure: %d IPs leased — reducing lease_time to %ds',
                    name, leased, self._lease_time_reduced,
                )
                self._push_config(name, url, {'lease_time': self._lease_time_reduced})

    def _get_json(self, url):
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                return json.loads(resp.read().decode())
        except Exception:
            return None

    def _push_config(self, name, url, config):
        body = json.dumps(config).encode()
        req  = urllib.request.Request(
            f'{url}/config',
            data=body,
            headers={'Content-Type': 'application/json'},
            method='PUT',
        )
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                result = json.loads(resp.read().decode())
            self.logger.info('[%s] config applied: %s', name, result)
        except Exception as exc:
            self.logger.error('[%s] config push failed: %s', name, exc)

    # Case 1: MAC_LEARNED - correlate with DHCP lease 

    def _on_mac_learned(self, event):
        mac    = event.get('mac')
        device = event.get('device')
        port   = event.get('port')
        # find dhcp_server URL
        dhcp = next((c for c in self._cnfs if c['name'] == 'dhcp_server'), None)
        if dhcp is None:
            return
        data = self._get_json(f"{dhcp['url']}/telemetry")
        if data is None:
            return
        leases = data.get('leases', {})
        entry  = leases.get(mac)
        ip     = entry['ip'] if entry else 'unknown'
        self.logger.info(
            '[mac_learned] device=%s port=%s mac=%s ip=%s',
            device, port, mac, ip,
        )

    def _on_cnf_config(self, payload):
        cnf_name = payload.get('cnf')
        config   = payload.get('config')

        if not cnf_name or config is None:
            self.logger.warning('CNF_CONFIG: invalid payload %s', payload)
            return

        cnf = next((c for c in self._cnfs if c['name'] == cnf_name), None)
        if cnf is None:
            self.logger.warning('CNF_CONFIG: unknown CNF "%s"', cnf_name)
            return

        url  = cnf['url']
        self._push_config(cnf_name, url, config)

    def shutdown(self):
        self._stop.set()


plugin = CnfControl
