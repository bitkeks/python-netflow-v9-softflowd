#!/usr/bin/env python3

"""
This file contains tests for the softflowd UDP collector saved in main.py The
test packets (defined below as hex streams) were extracted from a "real"
softflowd export based on a sample PCAP capture file. They consist of one
export with the templates and three without.

Copyright 2017-2020 Dominik Pataky <dev@bitkeks.eu>
Licensed under MIT License. See LICENSE.
"""

import json
import logging
import queue
import random
import socket
import subprocess
import sys
import time
import unittest

from main import NetFlowListener

# TODO: add tests for v1 and v5
# TODO: tests with 500 packets fail?

# The flowset with 2 templates and 8 flows
TEMPLATE_PACKET = '0009000a000000035c9f55980000000100000000000000400400000e00080004000c000400150004001600040001000400020004000a0004000e000400070002000b00020004000100060001003c000100050001000000400800000e001b0010001c001000150004001600040001000400020004000a0004000e000400070002000b00020004000100060001003c000100050001040001447f0000017f000001fb3c1aaafb3c18fd000190100000004b00000000000000000050942c061b04007f0000017f000001fb3c1aaafb3c18fd00000f94000000360000000000000000942c0050061f04007f0000017f000001fb3c1cfcfb3c1a9b0000d3fc0000002a000000000000000000509434061b04007f0000017f000001fb3c1cfcfb3c1a9b00000a490000001e000000000000000094340050061f04007f0000017f000001fb3bb82cfb3ba48b000002960000000300000000000000000050942a061904007f0000017f000001fb3bb82cfb3ba48b00000068000000020000000000000000942a0050061104007f0000017f000001fb3c1900fb3c18fe0000004c0000000100000000000000000035b3c9110004007f0000017f000001fb3c1900fb3c18fe0000003c000000010000000000000000b3c9003511000400'

# Three packets without templates, each with 12 flows, anonymized
PACKETS = [
    '0009000c000000035c9f55980000000200000000040001e47f0000017f000001fb3c1a17fb3c19fd000001480000000200000000000000000035ea82110004007f0000017f000001fb3c1a17fb3c19fd0000007a000000020000000000000000ea820035110004007f0000017f000001fb3c1a17fb3c19fd000000f80000000200000000000000000035c6e2110004007f0000017f000001fb3c1a17fb3c19fd0000007a000000020000000000000000c6e20035110004007f0000017f000001fb3c1a9efb3c1a9c0000004c0000000100000000000000000035adc1110004007f0000017f000001fb3c1a9efb3c1a9c0000003c000000010000000000000000adc10035110004007f0000017f000001fb3c1b74fb3c1b720000004c0000000100000000000000000035d0b3110004007f0000017f000001fb3c1b74fb3c1b720000003c000000010000000000000000d0b30035110004007f0000017f000001fb3c2f59fb3c1b7100001a350000000a000000000000000000509436061b04007f0000017f000001fb3c2f59fb3c1b710000038a0000000a000000000000000094360050061b04007f0000017f000001fb3c913bfb3c91380000004c0000000100000000000000000035e262110004007f0000017f000001fb3c913bfb3c91380000003c000000010000000000000000e262003511000400',
    '0009000c000000035c9f55980000000300000000040001e47f0000017f000001fb3ca523fb3c913b0000030700000005000000000000000000509438061b04007f0000017f000001fb3ca523fb3c913b000002a200000005000000000000000094380050061b04007f0000017f000001fb3f7fe1fb3dbc970002d52800000097000000000000000001bb8730061b04007f0000017f000001fb3f7fe1fb3dbc970000146c000000520000000000000000873001bb061f04007f0000017f000001fb3d066ffb3d066c0000004c0000000100000000000000000035e5bd110004007f0000017f000001fb3d066ffb3d066c0000003c000000010000000000000000e5bd0035110004007f0000017f000001fb3d1a61fb3d066b000003060000000500000000000000000050943a061b04007f0000017f000001fb3d1a61fb3d066b000002a2000000050000000000000000943a0050061b04007f0000017f000001fb3fed00fb3f002c0000344000000016000000000000000001bbae50061f04007f0000017f000001fb3fed00fb3f002c00000a47000000120000000000000000ae5001bb061b04007f0000017f000001fb402f17fb402a750003524c000000a5000000000000000001bbc48c061b04007f0000017f000001fb402f17fb402a75000020a60000007e0000000000000000c48c01bb061f0400',
    '0009000c000000035c9f55980000000400000000040001e47f0000017f000001fb3d7ba2fb3d7ba00000004c0000000100000000000000000035a399110004007f0000017f000001fb3d7ba2fb3d7ba00000003c000000010000000000000000a3990035110004007f0000017f000001fb3d8f85fb3d7b9f000003070000000500000000000000000050943c061b04007f0000017f000001fb3d8f85fb3d7b9f000002a2000000050000000000000000943c0050061b04007f0000017f000001fb3d9165fb3d7f6d0000c97b0000002a000000000000000001bbae48061b04007f0000017f000001fb3d9165fb3d7f6d000007f40000001a0000000000000000ae4801bb061b04007f0000017f000001fb3dbc96fb3dbc7e0000011e0000000200000000000000000035bd4f110004007f0000017f000001fb3dbc96fb3dbc7e0000008e000000020000000000000000bd4f0035110004007f0000017f000001fb3ddbb3fb3c1a180000bfee0000002f00000000000000000050ae56061b04007f0000017f000001fb3ddbb3fb3c1a1800000982000000270000000000000000ae560050061b04007f0000017f000001fb3ddbb3fb3c1a180000130e0000001200000000000000000050e820061b04007f0000017f000001fb3ddbb3fb3c1a180000059c000000140000000000000000e8200050061b0400'
]

INVALID_PACKET = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"

CONNECTION = ('127.0.0.1', 1337)
NUM_PACKETS = 50


def emit_packets(packets, delay=0):
    """Send the provided packets to the listener"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for p in packets:
        sock.sendto(bytes.fromhex(p), CONNECTION)
        time.sleep(delay)
    sock.close()


def send_recv_packets(packets, delay=0):
    """Starts a listener, send packets, receives packets

    returns a tuple: ([(ts, export), ...], time_started_sending, time_stopped_sending)
    """
    l = NetFlowListener(*CONNECTION)
    tstart = time.time()
    emit_packets(packets, delay=delay)
    time.sleep(0.5) # Allow packets to be sent and recieved
    tend = time.time()
    l.start()

    pkts = []
    while True:
        try:
            pkts.append(l.get(timeout=0.5))
        except queue.Empty:
            break
    l.stop()
    l.join()
    return pkts, tstart, tend


class TestSoftFlowExport(unittest.TestCase):

    def _test_recv_all_packets(self, num, template_idx, delay=0):
        """Fling packets at the server and test that it receives them all"""
        def gen_pkts(n, idx):
            for x in range(n):
                if x == idx:
                    yield TEMPLATE_PACKET
                else:
                    yield random.choice(PACKETS)

        pkts, tstart, tend = send_recv_packets(gen_pkts(num, template_idx), delay=delay)

        # check number of packets
        self.assertEqual(len(pkts), num)

        # check timestamps are when packets were sent, not processed
        self.assertTrue(all(tstart < p[0] < tend for p in pkts))

        # check number of "things" in the packets (flows + templates)
        # template packet = 10 things
        # other packets = 12 things
        self.assertEqual(sum(p[1].header.count for p in pkts), (num-1)*12 + 10)

        # check number of flows in the packets
        # template packet = 8 flows (2 templates)
        # other packets = 12 flows
        self.assertEqual(sum(len(p[1].flows) for p in pkts), (num-1)*12 + 8)

    def test_recv_all_packets_template_first(self):
        """Test all packets are received when the template is sent first"""
        self._test_recv_all_packets(NUM_PACKETS, 0)

    def test_recv_all_packets_template_middle(self):
        """Test all packets are received when the template is sent in the middle"""
        self._test_recv_all_packets(NUM_PACKETS, NUM_PACKETS//2)

    def test_recv_all_packets_template_last(self):
        """Test all packets are received when the template is sent last"""
        self._test_recv_all_packets(NUM_PACKETS, NUM_PACKETS-1)

    def test_recv_all_packets_slowly(self):
        """Test all packets are received when things are sent slooooowwwwwwwwlllllllyyyyyy"""
        self._test_recv_all_packets(3, 0, delay=1)

    def test_ignore_invalid_packets(self):
        """Test that invlalid packets log a warning but are otherwise ignored"""
        with self.assertLogs(level='WARNING'):
            pkts, _, _ = send_recv_packets([
                INVALID_PACKET, TEMPLATE_PACKET, random.choice(PACKETS), INVALID_PACKET,
                random.choice(PACKETS), INVALID_PACKET
            ])
        self.assertEqual(len(pkts), 3)

    def test_analyzer(self):
        """Test thar the analyzer doesn't break and outputs the correct number of lines"""
        pkts, _, _ = send_recv_packets([TEMPLATE_PACKET, *PACKETS])
        data = {p[0]: [f.data for f in p[1].flows] for p in pkts}
        analyzer = subprocess.run(
            [sys.executable, 'analyzer.py'],
            input=json.dumps(data),
            encoding='utf-8',
            capture_output=True
        )

        # every 2 flows are written as a single line (any extras are dropped)
        num_flows = sum(len(f) for f in data.values())
        self.assertEqual(len(analyzer.stdout.splitlines()), num_flows//2)

        # make sure there are no errors
        self.assertEqual(analyzer.stderr, "")


if __name__ == '__main__':
    unittest.main()
