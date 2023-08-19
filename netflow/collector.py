#!/usr/bin/env python3

"""
Reference collector script for NetFlow v1, v5, and v9 Python package.
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.

Copyright 2016-2020 Dominik Pataky <software+pynetflow@dpataky.eu>
Licensed under MIT License. See LICENSE.
"""
import argparse
import gzip
import json
import logging
import queue
import signal
import socket
import socketserver
import threading
import time
from collections import namedtuple

from netflow.ipfix import IPFIXTemplateNotRecognized
from netflow.utils import UnknownExportVersion, parse_packet
from netflow.v9 import V9TemplateNotRecognized

RawPacket = namedtuple('RawPacket', ['ts', 'client', 'data'])
ParsedPacket = namedtuple('ParsedPacket', ['ts', 'client', 'export'])

# Amount of time to wait before dropping an undecodable ExportPacket
PACKET_TIMEOUT = 60 * 60

logger = logging.getLogger("netflow-collector")
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


class QueuingRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]  # get content, [1] would be the socket
        self.server.queue.put(RawPacket(time.time(), self.client_address, data))
        logger.debug(
            "Received %d bytes of data from %s", len(data), self.client_address
        )


class QueuingUDPListener(socketserver.ThreadingUDPServer):
    """A threaded UDP server that adds a (time, data) tuple to a queue for
    every request it sees
    """

    def __init__(self, interface, queue):
        self.queue = queue

        # If IPv6 interface addresses are used, override the default AF_INET family
        if ":" in interface[0]:
            self.address_family = socket.AF_INET6

        super().__init__(interface, QueuingRequestHandler)


class ThreadedNetFlowListener(threading.Thread):
    """A thread that listens for incoming NetFlow packets, processes them, and
    makes them available to consumers.

    - When initialized, will start listening for NetFlow packets on the provided
      host and port and queuing them for processing.
    - When started, will start processing and parsing queued packets.
    - When stopped, will shut down the listener and stop processing.
    - When joined, will wait for the listener to exit

    For example, a simple script that outputs data until killed with CTRL+C:
    >>> listener = ThreadedNetFlowListener('0.0.0.0', 2055)
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

    def __init__(self, host: str, port: int):
        logger.info("Starting the NetFlow listener on {}:{}".format(host, port))
        self.output = queue.Queue()
        self.input = queue.Queue()
        self.server = QueuingUDPListener((host, port), self.input)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self._shutdown = threading.Event()
        super().__init__()

    def get(self, block=True, timeout=None) -> ParsedPacket:
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
            # TODO: use per-client templates
            templates = {"netflow": {}, "ipfix": {}}
            to_retry = []
            while not self._shutdown.is_set():
                try:
                    # 0.5s delay to limit CPU usage while waiting for new packets
                    pkt = self.input.get(block=True, timeout=0.5)  # type: RawPacket
                except queue.Empty:
                    continue

                try:
                    # templates is passed as reference, updated in V9ExportPacket
                    export = parse_packet(pkt.data, templates)
                except UnknownExportVersion as e:
                    logger.error("%s, ignoring the packet", e)
                    continue
                except (V9TemplateNotRecognized, IPFIXTemplateNotRecognized):
                    # TODO: differentiate between v9 and IPFIX, use separate to_retry lists
                    if time.time() - pkt.ts > PACKET_TIMEOUT:
                        logger.warning("Dropping an old and undecodable v9/IPFIX ExportPacket")
                    else:
                        to_retry.append(pkt)
                        logger.debug("Failed to decode a v9/IPFIX ExportPacket - will "
                                     "re-attempt when a new template is discovered")
                    continue

                if export.header.version == 10:
                    logger.debug("Processed an IPFIX ExportPacket with length %d.", export.header.length)
                else:
                    logger.debug("Processed a v%d ExportPacket with %d flows.",
                                 export.header.version, export.header.count)

                # If any new templates were discovered, dump the unprocessable
                # data back into the queue and try to decode them again
                if export.header.version in [9, 10] and export.contains_new_templates and to_retry:
                    logger.debug("Received new template(s)")
                    logger.debug("Will re-attempt to decode %d old v9/IPFIX ExportPackets", len(to_retry))
                    for p in to_retry:
                        self.input.put(p)
                    to_retry.clear()

                self.output.put(ParsedPacket(pkt.ts, pkt.client, export))
        finally:
            # Only reached when while loop ends
            self.server.shutdown()
            self.server.server_close()

    def stop(self):
        logger.info("Shutting down the NetFlow listener")
        self._shutdown.set()

    def join(self, timeout=None):
        self.thread.join(timeout=timeout)
        super().join(timeout=timeout)


def get_export_packets(host: str, port: int) -> ParsedPacket:
    """A threaded generator that will yield ExportPacket objects until it is killed
    """
    def handle_signal(s, f):
        logger.debug("Received signal {}, raising StopIteration".format(s))
        raise StopIteration
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    listener = ThreadedNetFlowListener(host, port)
    listener.start()

    try:
        while True:
            yield listener.get()
    except StopIteration:
        pass
    finally:
        listener.stop()
        listener.join()


if __name__ == "netflow.collector":
    logger.error("The collector is currently meant to be used as a CLI tool only.")
    logger.error("Use 'python3 -m netflow.collector -h' in your console for additional help.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A sample netflow collector.")
    parser.add_argument("--host", type=str, default="0.0.0.0",
                        help="collector listening address")
    parser.add_argument("--port", "-p", type=int, default=2055,
                        help="collector listener port")
    parser.add_argument("--file", "-o", type=str, dest="output_file",
                        default="{}.gz".format(int(time.time())),
                        help="collector export multiline JSON file")
    parser.add_argument("--debug", "-D", action="store_true",
                        help="Enable debug output")
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)

    try:
        # With every parsed flow a new line is appended to the output file. In previous versions, this was implemented
        # by storing the whole data dict in memory and dumping it regularly onto disk. This was extremely fragile, as
        # it a) consumed a lot of memory and CPU (dropping packets since storing one flow took longer than the arrival
        # of the next flow) and b) broke the exported JSON file, if the collector crashed during the write process,
        # rendering all collected flows during the runtime of the collector useless (the file contained one large JSON
        # dict which represented the 'data' dict).

        # In this new approach, each received flow is parsed as usual, but it gets appended to a gzipped file each time.
        # All in all, this improves in three aspects:
        # 1. collected flow data is not stored in memory any more
        # 2. received and parsed flows are persisted reliably
        # 3. the disk usage of files with JSON and its full strings as keys is reduced by using gzipped files
        # This also means that the files have to be handled differently, because they are gzipped and not formatted as
        # one single big JSON dump, but rather many little JSON dumps, separated by line breaks.
        for ts, client, export in get_export_packets(args.host, args.port):
            entry = {ts: {
                "client": client,
                "header": export.header.to_dict(),
                "flows": [flow.data for flow in export.flows]}
            }
            line = json.dumps(entry).encode() + b"\n"  # byte encoded line
            with gzip.open(args.output_file, "ab") as fh:  # open as append, not reading the whole file
                fh.write(line)
    except KeyboardInterrupt:
        logger.info("Received KeyboardInterrupt, passing through")
        pass
