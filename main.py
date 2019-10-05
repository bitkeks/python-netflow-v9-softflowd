#!/usr/bin/env python3

"""
Example collector script for NetFlow v9.
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.

Copyright 2017-2019 Dominik Pataky <dev@bitkeks.eu>
Licensed under MIT License. See LICENSE.
"""

import argparse
from collections import namedtuple
from queue import Queue
import json
import logging
import sys
import socketserver
import threading
import time

from netflow.v9 import ExportPacket, TemplateNotRecognized


__log__ = logging.getLogger(__name__)

# Amount of time to wait before dropping an undecodable ExportPacket
PACKET_TIMEOUT = 60 * 60

RawPacket = namedtuple('RawPacket', ['ts', 'data'])

class QueuingRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        self.server.queue.put(RawPacket(time.time(), data))
        __log__.debug(
            "Recieved %d bytes of data from %s", len(data), self.client_address[0]
        )


class QueuingUDPListener(socketserver.ThreadingUDPServer):
    """A threaded UDP server that adds a (time, data) tuple to a queue for
    every request it sees
    """
    def __init__(self, interface, queue):
        self.queue = queue
        super().__init__(interface, QueuingRequestHandler)


def get_export_packets(host, port):
    """A generator that will yield ExportPacket objects until it is killed
    or has a truthy value sent to it"""

    __log__.info("Starting the NetFlow listener on {}:{}".format(host, port))
    queue = Queue()
    server = QueuingUDPListener((host, port), queue)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()

    # Process packets from the queue
    templates = {}
    to_retry = []
    try:
        while True:
            pkt = queue.get()
            try:
                export = ExportPacket(pkt.data, templates)
            except TemplateNotRecognized:
                if time.time() - pkt.ts > PACKET_TIMEOUT:
                    __log__.warning("Dropping an old and undecodable ExportPacket")
                else:
                    to_retry.append(pkt)
                    __log__.debug("Failed to decode an ExportPacket - will "
                                  "re-attempt when a new template is dicovered")
                continue

            __log__.debug("Processed an ExportPacket with %d flows.",
                          export.header.count)

            # If any new templates were discovered, dump the unprocessable
            # data back into the queue and try to decode them again
            if export.contains_new_templates and to_retry:
                __log__.debug("Recieved new template(s)")
                __log__.debug("Will re-attempt to decode %d old ExportPackets",
                              len(to_retry))
                for p in to_retry:
                    queue.put(p)
                to_retry.clear()

            stop = yield pkt.ts, export
            if stop:
                break
    finally:
        __log__.info("Shutting down the NetFlow listener")
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A sample netflow collector.")
    parser.add_argument("--host", type=str, default="0.0.0.0",
                        help="collector listening address")
    parser.add_argument("--port", "-p", type=int, default=2055,
                        help="collector listener port")
    parser.add_argument("--file", "-o", type=str, dest="output_file",
                        default="{}.json".format(int(time.time())),
                        help="collector export JSON file")
    parser.add_argument("--debug", "-D", action="store_true",
                        help="Enable debug output")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(message)s")

    if args.debug:
        __log__.setLevel(logging.DEBUG)

    data = {}
    try:
        # TODO: For a long-running processes, this will consume loads of memory
        for ts, export in get_export_packets(args.host, args.port):
            data[ts] = [flow.data for flow in export.flows]
    except KeyboardInterrupt:
        pass

    if data:
        __log__.info("Outputting collected data to '%s'", args.output_file)
        with open(args.output_file, 'w') as f:
            json.dump(data, f)
    else:
        __log__.info("No data collected")
