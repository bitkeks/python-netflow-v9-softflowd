#!/usr/bin/env python3

"""
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.

Copyright 2016-2020 Dominik Pataky <dev@bitkeks.eu>
Licensed under MIT License. See LICENSE.
"""
# TODO: tests with 500 packets fail with delay=0. Probably a problem with UDP sockets buffer

import ipaddress
import random
import unittest

from tests.lib import *


class TestFlowExportNetflow(unittest.TestCase):
    def _test_recv_all_packets(self, num, template_idx, delay=0.0001):
        """Fling packets at the server and test that it receives them all"""

        def gen_pkts(n, idx):
            for x in range(n):
                if x == idx:
                    yield PACKET_V9_TEMPLATE
                else:
                    yield random.choice(PACKETS_V9)

        pkts, tstart, tend = send_recv_packets(gen_pkts(num, template_idx), delay=delay)

        # check number of packets
        self.assertEqual(len(pkts), num)

        # check timestamps are when packets were sent, not processed
        self.assertTrue(all(tstart < p.ts < tend for p in pkts))

        # check number of "things" in the packets (flows + templates)
        # template packet = 10 things
        # other packets = 12 things
        self.assertEqual(sum(p.export.header.count for p in pkts), (num - 1) * 12 + 10)

        # check number of flows in the packets
        # template packet = 8 flows (2 templates)
        # other packets = 12 flows
        self.assertEqual(sum(len(p.export.flows) for p in pkts), (num - 1) * 12 + 8)

    def test_recv_all_packets_template_first(self):
        """Test all packets are received when the template is sent first"""
        self._test_recv_all_packets(NUM_PACKETS, 0)

    def test_recv_all_packets_template_middle(self):
        """Test all packets are received when the template is sent in the middle"""
        self._test_recv_all_packets(NUM_PACKETS, NUM_PACKETS // 2)

    def test_recv_all_packets_template_last(self):
        """Test all packets are received when the template is sent last"""
        self._test_recv_all_packets(NUM_PACKETS, NUM_PACKETS - 1)

    def test_recv_all_packets_slowly(self):
        """Test all packets are received when things are sent slooooowwwwwwwwlllllllyyyyyy"""
        self._test_recv_all_packets(3, 0, delay=1)

    def test_ignore_invalid_packets(self):
        """Test that invalid packets log a warning but are otherwise ignored"""
        with self.assertLogs(level='WARNING'):
            pkts, _, _ = send_recv_packets([
                PACKET_INVALID, PACKET_V9_TEMPLATE, random.choice(PACKETS_V9), PACKET_INVALID,
                random.choice(PACKETS_V9), PACKET_INVALID
            ])
        self.assertEqual(len(pkts), 3)

    def test_recv_v1_packet(self):
        """Test NetFlow v1 packet parsing"""
        pkts, _, _ = send_recv_packets([PACKET_V1])
        self.assertEqual(len(pkts), 1)

        # Take the parsed packet and check meta data
        p = pkts[0]
        self.assertEqual(p.client[0], "127.0.0.1")  # collector listens locally
        self.assertEqual(len(p.export.flows), 2)  # ping request and reply
        self.assertEqual(p.export.header.count, 2)  # same value, in header
        self.assertEqual(p.export.header.version, 1)

        # Check specific IP address contained in a flow.
        # Since it might vary which flow of the pair is epxorted first, check both
        flow = p.export.flows[0]
        self.assertIn(
            ipaddress.ip_address(flow.IPV4_SRC_ADDR),  # convert to ipaddress obj because value is int
            [ipaddress.ip_address("172.17.0.1"), ipaddress.ip_address("172.17.0.2")]
        )
        self.assertEqual(flow.PROTO, 1)  # ICMP

    def test_recv_v5_packet(self):
        """Test NetFlow v5 packet parsing"""
        pkts, _, _ = send_recv_packets([PACKET_V5])
        self.assertEqual(len(pkts), 1)

        p = pkts[0]
        self.assertEqual(p.client[0], "127.0.0.1")
        self.assertEqual(len(p.export.flows), 3)  # ping request and reply, one multicast
        self.assertEqual(p.export.header.count, 3)
        self.assertEqual(p.export.header.version, 5)

        # Check specific IP address contained in a flow.
        # Since it might vary which flow of the pair is epxorted first, check both
        flow = p.export.flows[0]
        self.assertIn(
            ipaddress.ip_address(flow.IPV4_SRC_ADDR),  # convert to ipaddress obj because value is int
            [ipaddress.ip_address("172.17.0.1"), ipaddress.ip_address("172.17.0.2")]  # matches multicast packet too
        )
        self.assertEqual(flow.PROTO, 1)  # ICMP

    def test_recv_v9_packet(self):
        """Test NetFlow v9 packet parsing"""

        # send packet without any template, must fail to parse (packets are queued)
        pkts, _, _ = send_recv_packets([PACKETS_V9[0]])
        self.assertEqual(len(pkts), 0)  # no export is parsed due to missing template

        # send packet with two templates and eight flows, should parse correctly since the templates are known
        pkts, _, _ = send_recv_packets([PACKET_V9_TEMPLATE])
        self.assertEqual(len(pkts), 1)

        # and again, but with the templates at the end in the packet
        pkts, _, _ = send_recv_packets([PACKET_V9_TEMPLATE_MIXED])
        self.assertEqual(len(pkts), 1)
        p = pkts[0]
        self.assertEqual(p.client[0], "127.0.0.1")
        self.assertEqual(len(p.export.flows), 8)  # count flows
        self.assertEqual(len(p.export.templates), 2)  # count new templates

        # Inspect contents of specific flows
        flow = p.export.flows[0]
        self.assertEqual(flow.PROTOCOL, 6)  # TCP
        self.assertEqual(flow.L4_SRC_PORT, 80)
        self.assertEqual(flow.IPV4_SRC_ADDR, "127.0.0.1")

        flow = p.export.flows[-1]  # last flow
        self.assertEqual(flow.PROTOCOL, 17)  # UDP
        self.assertEqual(flow.L4_DST_PORT, 53)

        # send template and multiple export packets
        pkts, _, _ = send_recv_packets([PACKET_V9_TEMPLATE, *PACKETS_V9])
        self.assertEqual(len(pkts), 4)
        self.assertEqual(pkts[0].export.header.version, 9)

        # check amount of flows across all packets
        total_flows = 0
        for packet in pkts:
            total_flows += len(packet.export.flows)
        self.assertEqual(total_flows, 8 + 12 + 12 + 12)


if __name__ == '__main__':
    unittest.main()
