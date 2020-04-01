"""
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.

The test packets (defined below as hex streams) were extracted from "real"
softflowd exports based on a sample PCAP capture file.

Copyright 2016-2020 Dominik Pataky <dev@bitkeks.eu>
Licensed under MIT License. See LICENSE.
"""

# The flowset with 2 templates (IPv4 and IPv6) and 8 flows with data
import queue
import socket
import time

from netflow.collector import ThreadedNetFlowListener


# Invalid export hex stream
PACKET_INVALID = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"

CONNECTION = ('127.0.0.1', 1337)
NUM_PACKETS = 100


def emit_packets(packets, delay=0.0001):
    """Send the provided packets to the listener"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for p in packets:
        sock.sendto(bytes.fromhex(p), CONNECTION)
        time.sleep(delay)
    sock.close()


def send_recv_packets(packets, delay=0.0001) -> (list, float, float):
    """Starts a listener, send packets, receives packets

    returns a tuple: ([(ts, export), ...], time_started_sending, time_stopped_sending)
    """
    listener = ThreadedNetFlowListener(*CONNECTION)
    tstart = time.time()
    emit_packets(packets, delay=delay)
    time.sleep(0.5)  # Allow packets to be sent and recieved
    tend = time.time()
    listener.start()

    pkts = []
    while True:
        try:
            pkts.append(listener.get(timeout=0.5))
        except queue.Empty:
            break
    listener.stop()
    listener.join()
    return pkts, tstart, tend
