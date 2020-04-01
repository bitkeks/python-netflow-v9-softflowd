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


# Example export for v1 which contains two flows from one ICMP ping request/reply session
PACKET_V1 = "000100020001189b5e80c32c2fd41848ac110002ac11000100000000000000000000000a00000348" \
            "000027c700004af100000800000001000000000000000000ac110001ac1100020000000000000000" \
            "0000000a00000348000027c700004af100000000000001000000000000000000"

# Example export for v5 which contains three flows, two for ICMP ping and one multicast on interface (224.0.0.251)
PACKET_V5 = "00050003000379a35e80c58622a55ab00000000000000000ac110002ac1100010000000000000000" \
            "0000000a0000034800002f4c0000527600000800000001000000000000000000ac110001ac110002" \
            "00000000000000000000000a0000034800002f4c0000527600000000000001000000000000000000" \
            "ac110001e00000fb000000000000000000000001000000a90000e01c0000e01c14e914e900001100" \
            "0000000000000000"

PACKET_V9_TEMPLATE = "0009000a000000035c9f55980000000100000000000000400400000e00080004000c000400150004" \
                     "001600040001000400020004000a0004000e000400070002000b00020004000100060001003c0001" \
                     "00050001000000400800000e001b0010001c001000150004001600040001000400020004000a0004" \
                     "000e000400070002000b00020004000100060001003c000100050001040001447f0000017f000001" \
                     "fb3c1aaafb3c18fd000190100000004b00000000000000000050942c061b04007f0000017f000001" \
                     "fb3c1aaafb3c18fd00000f94000000360000000000000000942c0050061f04007f0000017f000001" \
                     "fb3c1cfcfb3c1a9b0000d3fc0000002a000000000000000000509434061b04007f0000017f000001" \
                     "fb3c1cfcfb3c1a9b00000a490000001e000000000000000094340050061f04007f0000017f000001" \
                     "fb3bb82cfb3ba48b000002960000000300000000000000000050942a061904007f0000017f000001" \
                     "fb3bb82cfb3ba48b00000068000000020000000000000000942a0050061104007f0000017f000001" \
                     "fb3c1900fb3c18fe0000004c0000000100000000000000000035b3c9110004007f0000017f000001" \
                     "fb3c1900fb3c18fe0000003c000000010000000000000000b3c9003511000400"

# This packet is special. We take PACKET_V9_TEMPLATE and re-order the templates and flows.
# The first line is the header, the smaller lines the templates and the long lines the flows (limited to 80 chars)
PACKET_V9_TEMPLATE_MIXED = ("0009000a000000035c9f55980000000100000000"  # header
                            "040001447f0000017f000001fb3c1aaafb3c18fd000190100000004b00000000000000000050942c"
                            "061b04007f0000017f000001fb3c1aaafb3c18fd00000f94000000360000000000000000942c0050"
                            "061f04007f0000017f000001fb3c1cfcfb3c1a9b0000d3fc0000002a000000000000000000509434"
                            "061b04007f0000017f000001fb3c1cfcfb3c1a9b00000a490000001e000000000000000094340050"
                            "061f04007f0000017f000001fb3bb82cfb3ba48b000002960000000300000000000000000050942a"
                            "061904007f0000017f000001fb3bb82cfb3ba48b00000068000000020000000000000000942a0050"
                            "061104007f0000017f000001fb3c1900fb3c18fe0000004c0000000100000000000000000035b3c9"
                            "110004007f0000017f000001fb3c1900fb3c18fe0000003c000000010000000000000000b3c90035"
                            "11000400"  # end of flow segments
                            "000000400400000e00080004000c000400150004001600040001000400020004"  # template 1024
                            "000a0004000e000400070002000b00020004000100060001003c000100050001"
                            "000000400800000e001b0010001c001000150004001600040001000400020004"  # template 2048
                            "000a0004000e000400070002000b00020004000100060001003c000100050001")

# Three packets without templates, each with 12 flows, anonymized
PACKETS_V9 = [
    "0009000c000000035c9f55980000000200000000040001e47f0000017f000001fb3c1a17fb3c19fd"
    "000001480000000200000000000000000035ea82110004007f0000017f000001fb3c1a17fb3c19fd"
    "0000007a000000020000000000000000ea820035110004007f0000017f000001fb3c1a17fb3c19fd"
    "000000f80000000200000000000000000035c6e2110004007f0000017f000001fb3c1a17fb3c19fd"
    "0000007a000000020000000000000000c6e20035110004007f0000017f000001fb3c1a9efb3c1a9c"
    "0000004c0000000100000000000000000035adc1110004007f0000017f000001fb3c1a9efb3c1a9c"
    "0000003c000000010000000000000000adc10035110004007f0000017f000001fb3c1b74fb3c1b72"
    "0000004c0000000100000000000000000035d0b3110004007f0000017f000001fb3c1b74fb3c1b72"
    "0000003c000000010000000000000000d0b30035110004007f0000017f000001fb3c2f59fb3c1b71"
    "00001a350000000a000000000000000000509436061b04007f0000017f000001fb3c2f59fb3c1b71"
    "0000038a0000000a000000000000000094360050061b04007f0000017f000001fb3c913bfb3c9138"
    "0000004c0000000100000000000000000035e262110004007f0000017f000001fb3c913bfb3c9138"
    "0000003c000000010000000000000000e262003511000400",

    "0009000c000000035c9f55980000000300000000040001e47f0000017f000001fb3ca523fb3c913b"
    "0000030700000005000000000000000000509438061b04007f0000017f000001fb3ca523fb3c913b"
    "000002a200000005000000000000000094380050061b04007f0000017f000001fb3f7fe1fb3dbc97"
    "0002d52800000097000000000000000001bb8730061b04007f0000017f000001fb3f7fe1fb3dbc97"
    "0000146c000000520000000000000000873001bb061f04007f0000017f000001fb3d066ffb3d066c"
    "0000004c0000000100000000000000000035e5bd110004007f0000017f000001fb3d066ffb3d066c"
    "0000003c000000010000000000000000e5bd0035110004007f0000017f000001fb3d1a61fb3d066b"
    "000003060000000500000000000000000050943a061b04007f0000017f000001fb3d1a61fb3d066b"
    "000002a2000000050000000000000000943a0050061b04007f0000017f000001fb3fed00fb3f002c"
    "0000344000000016000000000000000001bbae50061f04007f0000017f000001fb3fed00fb3f002c"
    "00000a47000000120000000000000000ae5001bb061b04007f0000017f000001fb402f17fb402a75"
    "0003524c000000a5000000000000000001bbc48c061b04007f0000017f000001fb402f17fb402a75"
    "000020a60000007e0000000000000000c48c01bb061f0400",

    "0009000c000000035c9f55980000000400000000040001e47f0000017f000001fb3d7ba2fb3d7ba0"
    "0000004c0000000100000000000000000035a399110004007f0000017f000001fb3d7ba2fb3d7ba0"
    "0000003c000000010000000000000000a3990035110004007f0000017f000001fb3d8f85fb3d7b9f"
    "000003070000000500000000000000000050943c061b04007f0000017f000001fb3d8f85fb3d7b9f"
    "000002a2000000050000000000000000943c0050061b04007f0000017f000001fb3d9165fb3d7f6d"
    "0000c97b0000002a000000000000000001bbae48061b04007f0000017f000001fb3d9165fb3d7f6d"
    "000007f40000001a0000000000000000ae4801bb061b04007f0000017f000001fb3dbc96fb3dbc7e"
    "0000011e0000000200000000000000000035bd4f110004007f0000017f000001fb3dbc96fb3dbc7e"
    "0000008e000000020000000000000000bd4f0035110004007f0000017f000001fb3ddbb3fb3c1a18"
    "0000bfee0000002f00000000000000000050ae56061b04007f0000017f000001fb3ddbb3fb3c1a18"
    "00000982000000270000000000000000ae560050061b04007f0000017f000001fb3ddbb3fb3c1a18"
    "0000130e0000001200000000000000000050e820061b04007f0000017f000001fb3ddbb3fb3c1a18"
    "0000059c000000140000000000000000e8200050061b0400"
]


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
