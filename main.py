#!/usr/bin/env python3

"""
Example collector script for NetFlow v9.
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.

Copyright 2017-2019 Dominik Pataky <dev@bitkeks.eu>
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
    from netflow.collector_v9 import ExportPacket, TemplateNotRecognized
except ImportError:
    logging.warning("Netflow v9 not installed as package! Running from directory.")
    from src.netflow.collector_v9 import ExportPacket, TemplateNotRecognized

parser = argparse.ArgumentParser(description="A sample netflow collector.")
parser.add_argument("--host", type=str, default="",
                    help="collector listening address")
parser.add_argument("--port", "-p", type=int, default=2055,
                    help="collector listener port")
parser.add_argument("--file", "-o", type=str, dest="output_file",
                    default="{}.json".format(int(time.time())),
                    help="collector export JSON file")
parser.add_argument("--debug", "-D", action="store_true",
                    help="Enable debug output")


class SoftflowUDPHandler(socketserver.BaseRequestHandler):
    # We need to save the templates our NetFlow device
    # send over time. Templates are not resended every
    # time a flow is sent to the collector.
    templates = {}
    buffered = {}

    @classmethod
    def set_output_file(cls, path):
        cls.output_file = path

    def handle(self):
        if not os.path.exists(self.output_file):
            with open(self.output_file, 'w') as fh:
                json.dump({}, fh)

        with open(self.output_file, 'r') as fh:
            try:
                existing_data = json.load(fh)
            except json.decoder.JSONDecodeError as ex:
                logging.error("Malformed JSON output file. Cannot read existing data, aborting.")
                return

        data = self.request[0]
        host = self.client_address[0]
        logging.debug("Received data from {}, length {}".format(host, len(data)))

        export = None
        try:
            export = ExportPacket(data, self.templates)
        except TemplateNotRecognized:
            self.buffered[time.time()] = data
            logging.warning("Received data with unknown template, data stored in buffer!")
            return

        if not export:
            logging.error("Error with exception handling while disecting export, export is None")
            return

        logging.debug("Processed ExportPacket with {} flows.".format(export.header.count))
        logging.debug("Size of buffer: {}".format(len(self.buffered)))

        # In case the export held some new templates
        self.templates.update(export.templates)

        remain_buffered = {}
        processed = []
        for timestamp, data in self.buffered.items():
            try:
                buffered_export = ExportPacket(data, self.templates)
                processed.append(timestamp)
            except TemplateNotRecognized:
                remain_buffered[timestamp] = data
                logging.debug("Template of buffered ExportPacket still not recognized")
                continue
            logging.debug("Processed buffered ExportPacket with {} flows.".format(buffered_export.header.count))
            existing_data[timestamp] = [flow.data for flow in buffered_export.flows]

        # Delete processed items from the buffer
        for pro in processed:
            del self.buffered[pro]

        # Update the buffer
        self.buffered.update(remain_buffered)

        # Append new flows
        existing_data[time.time()] = [flow.data for flow in export.flows]

        with open(self.output_file, 'w') as fh:
            json.dump(existing_data, fh)



if __name__ == "__main__":
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    output_file = args.output_file
    SoftflowUDPHandler.set_output_file(output_file)

    host = args.host
    port = args.port
    logging.info("Listening on interface {}:{}".format(host, port))
    server = socketserver.UDPServer((host, port), SoftflowUDPHandler)

    try:
        logging.debug("Starting the NetFlow listener")
        server.serve_forever(poll_interval=0.5)
    except (IOError, SystemExit):
        raise
    except KeyboardInterrupt:
        raise

    server.server_close()
