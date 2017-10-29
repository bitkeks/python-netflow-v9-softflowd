#!/usr/bin/env python3

"""
Example collector script for NetFlow v9.
This file belongs to https://github.com/cooox/python-netflow-v9-softflowd.

Copyright 2017 Dominik Pataky <dom@netdecorator.org>
Licensed under MIT License. See LICENSE.
"""

import logging
import argparse
import sys
import socketserver
import time
import json
import os.path


logging.getLogger().setLevel(logging.INFO)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(message)s')
ch.setFormatter(formatter)
logging.getLogger().addHandler(ch)

try:
    from netflow.collector_v9 import ExportPacket
except ImportError:
    logging.warn("Netflow v9 not installed as package! Running from directory.")
    from src.netflow.collector_v9 import ExportPacket

parser = argparse.ArgumentParser(description='A sample netflow collector.')
parser.add_argument('--host', type=str, default='',
                    help='collector listening address')
parser.add_argument('--port', '-p', type=int, default=2055,
                    help='collector listener port')
parser.add_argument('--file', '-o', type=str, dest='output_file',
                    default="{}.json".format(int(time.time())),
                    help='collector export JSON file')
parser.add_argument('--debug', '-D', action='store_true',
                    help='Enable debug output')

class SoftflowUDPHandler(socketserver.BaseRequestHandler):
    # We need to save the templates our NetFlow device
    # send over time. Templates are not resended every
    # time a flow is sent to the collector.
    TEMPLATES = {}

    @classmethod
    def get_server(cls, host, port):
        logging.info("Listening on interface {}:{}".format(host, port))
        server = socketserver.UDPServer((host, port), cls)
        return server

    @classmethod
    def set_output_file(cls, path):
        cls.output_file = path

    def handle(self):
        if not os.path.exists(self.output_file):
            with open(self.output_file, 'w') as fh:
                fh.write(json.dumps({}))

        with open(self.output_file, 'r') as fh:
            existing_data = json.loads(fh.read())

        data = self.request[0]
        host = self.client_address[0]
        s = "Received data from {}, length {}".format(host, len(data))
        logging.debug(s)
        export = ExportPacket(data, self.TEMPLATES)
        self.TEMPLATES.update(export.templates)
        s = "Processed ExportPacket with {} flows.".format(export.header.count)
        logging.debug(s)

        # Append new flows
        existing_data[time.time()] = [flow.data for flow in export.flows]

        with open(self.output_file, 'w') as fh:
            fh.write(json.dumps(existing_data))



if __name__ == "__main__":
    args = parser.parse_args()
    SoftflowUDPHandler.set_output_file(args.output_file)
    server = SoftflowUDPHandler.get_server(args.host, args.port)

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        logging.debug("Starting the NetFlow listener")
        server.serve_forever(poll_interval=0.5)
    except (IOError, SystemExit):
        raise
    except KeyboardInterrupt:
        raise
