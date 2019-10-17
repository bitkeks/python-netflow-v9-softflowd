#!/usr/bin/env python3

"""
Example collector script for NetFlow v9.
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.

Copyright 2017-2019 Dominik Pataky <dev@bitkeks.eu>
Licensed under MIT License. See LICENSE.
"""

import argparse
from collections import namedtuple
import queue
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


class NetFlowListener(threading.Thread):
    """A thread that listens for incoming NetFlow packets, processes them, and
    makes them available to consumers.

    - When initialized, will start listening for NetFlow packets on the provided
      host and port and queuing them for processing.
    - When started, will start processing and parsing queued packets.
    - When stopped, will shut down the listener and stop processing.
    - When joined, will wait for the listener to exit

    For example, a simple script that outputs data until killed with CTRL+C:
    >>> listener = NetFlowListener('0.0.0.0', 2055)
    >>> print("Listening for NetFlow packets")
    >>> listener.start() # start processing packets
    >>> try:
    ...     while True:
    ...         ts, export = listener.get()
    ...         print("Time: {}".format(ts))
    ...         for f in export.flows:
    ...             print(" - {IPV4_SRC_ADDR} sent data to {IPV4_DST_ADDR}"
    ...                   "".format(**f))
    ... finally:
    ...     print("Stopping...")
    ...     listener.stop()
    ...     listener.join()
    ...     print("Stopped!")
    """

    def __init__(self, host, port):
        __log__.info("Starting the NetFlow listener on {}:{}".format(host, port))
        self.output = queue.Queue()
        self.input = queue.Queue()
        self.server = QueuingUDPListener((host, port), self.input)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self._shutdown = threading.Event()
        super().__init__()

    def get(self, block=True, timeout=None):
        """Get a processed flow.

        If optional args 'block' is true and 'timeout' is None (the default),
        block if necessary until a flow is available. If 'timeout' is
        a non-negative number, it blocks at most 'timeout' seconds and raises
        the queue.Empty exception if no flow was available within that time.
        Otherwise ('block' is false), return a flow if one is immediately
        available, else raise the queue.Empty exception ('timeout' is ignored
        in that case).
        """
        return self.output.get(block, timeout)

    def run(self):
        # Process packets from the queue
        try:
            templates = {}
            to_retry = []
            while not self._shutdown.is_set():
                try:
                    # 0.5s delay to limit CPU usage while waiting for new packets
                    pkt = self.input.get(block=True, timeout=0.5)
                except queue.Empty:
                    continue

                try:
                    export = ExportPacket(pkt.data, templates)
                except TemplateNotRecognized:
                    if time.time() - pkt.ts > PACKET_TIMEOUT:
                        __log__.warning("Dropping an old and undecodable ExportPacket")
                    else:
                        to_retry.append(pkt)
                        __log__.debug("Failed to decode a ExportPacket - will "
                                      "re-attempt when a new template is discovered")
                    continue

                __log__.debug("Processed an ExportPacket with %d flows.",
                              export.header.version, export.header.count)

                # If any new templates were discovered, dump the unprocessable
                # data back into the queue and try to decode them again
                if export.contains_new_templates and to_retry:
                    __log__.debug("Received new template(s)")
                    __log__.debug("Will re-attempt to decode %d old v9 ExportPackets",
                                  len(to_retry))
                    for p in to_retry:
                        self.input.put(p)
                    to_retry.clear()

                self.output.put((pkt.ts, export))
        finally:
            self.server.shutdown()
            self.server.server_close()

    def stop(self):
        __log__.info("Shutting down the NetFlow listener")
        self._shutdown.set()

    def join(self):
        self.thread.join()
        super().join()


def get_export_packets(host, port):
    """A generator that will yield ExportPacket objects until it is killed"""

    listener = NetFlowListener(host, port)
    listener.start()
    try:
        while True:
            yield listener.get()
    finally:
        listener.stop()
        listener.join()


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
