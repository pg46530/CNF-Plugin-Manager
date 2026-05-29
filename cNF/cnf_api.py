"""
cnf_api.py — Shared REST API base for all CNFs.

Provides /health, /telemetry, and /config (GET + PUT) endpoints via Flask,
running in a daemon thread so the main thread can run the packet loop.
"""

import json
import threading

from flask import Flask, Response, request


class CnfApi:

    def __init__(self, name, port, get_telemetry, get_config, set_config):
        self._name = name
        self._port = port
        self._get_telemetry = get_telemetry
        self._get_config = get_config
        self._set_config = set_config

    def start(self):
        """Start the Flask server in a daemon thread (returns immediately)."""
        app = self._build_app()
        t = threading.Thread(
            target=app.run,
            kwargs={'host': '0.0.0.0', 'port': self._port, 'threaded': True},
            daemon=True,
            name=f'{self._name}-api',
        )
        t.start()

    def _json_response(self, data, status=200):
        return Response(
            json.dumps(data),
            status=status,
            mimetype='application/json',
        )

    def _build_app(self):
        app = Flask(self._name)
        app.logger.disabled = True          # suppress Flask request logs

        @app.route('/health')
        def health():
            return self._json_response({'status': 'OK'})

        @app.route('/telemetry')
        def telemetry():
            return self._json_response(self._get_telemetry())

        @app.route('/config', methods=['GET'])
        def get_config():
            return self._json_response(self._get_config())

        @app.route('/config', methods=['PUT'])
        def put_config():
            try:
                data = request.get_json(force=True)
            except Exception:
                return self._json_response({'error': 'invalid JSON'}, 400)
            err = self._set_config(data)
            if err:
                return self._json_response({'error': err}, 400)
            return self._json_response({
                'status': 'applied',
                'config': self._get_config(),
            })

        return app
