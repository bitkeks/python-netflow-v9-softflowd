#!/usr/bin/env python3

"""
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.

Copyright 2016-2020 Dominik Pataky <dev@bitkeks.eu>
Licensed under MIT License. See LICENSE.
"""
# TODO: tests with 500 packets fail with delay=0. Probably a problem with UDP sockets buffer
# TODO: add test for template withdrawal

import ipaddress
import unittest

from tests.lib import send_recv_packets, PACKET_IPFIX_TEMPLATE, PACKET_IPFIX, PACKET_IPFIX_ETHER, \
    PACKET_IPFIX_TEMPLATE_ETHER


class TestFlowExportIPFIX(unittest.TestCase):
    def test_recv_ipfix_packet(self):
        """
        Test general sending of raw and receiving and parsing of these packets.
        If this test runs successfully, the sender thread has sent a raw bytes packet towards a locally
        listening collector thread, and the collector has successfully received and parsed the packets.
        :return:
        """
        # send packet without any template, must fail to parse (packets are queued)
        pkts, _, _ = send_recv_packets([PACKET_IPFIX])
        self.assertEqual(len(pkts), 0)  # no export is parsed due to missing template

        # send packet with 5 templates and 20 flows, should parse correctly since the templates are known
        pkts, _, _ = send_recv_packets([PACKET_IPFIX_TEMPLATE])
        self.assertEqual(len(pkts), 1)

        p = pkts[0]
        self.assertEqual(p.client[0], "127.0.0.1")
        self.assertEqual(len(p.export.flows), 1 + 2 + 2 + 9 + 1 + 2 + 1 + 2)  # count flows
        self.assertEqual(len(p.export.templates), 4 + 1)  # count new templates

        # send template and multiple export packets
        pkts, _, _ = send_recv_packets([PACKET_IPFIX, PACKET_IPFIX_TEMPLATE, PACKET_IPFIX])
        self.assertEqual(len(pkts), 3)
        self.assertEqual(pkts[0].export.header.version, 10)

        # check amount of flows across all packets
        total_flows = 0
        for packet in pkts:
            total_flows += len(packet.export.flows)
        self.assertEqual(total_flows, 2 + 1 + (1 + 2 + 2 + 9 + 1 + 2 + 1 + 2) + 2 + 1)

    def test_ipfix_contents(self):
        """
        Inspect content of exported flows, eg. test the value of an option flow and the correct
        parsing of IPv4 and IPv6 addresses.
        :return:
        """
        p = send_recv_packets([PACKET_IPFIX_TEMPLATE])[0][0]

        flow = p.export.flows[0]
        self.assertEqual(flow.meteringProcessId, 2649)
        self.assertEqual(flow.selectorAlgorithm, 1)
        self.assertEqual(flow.systemInitTimeMilliseconds, 1585735165729)

        flow = p.export.flows[1]  # HTTPS flow from web server to client
        self.assertEqual(flow.destinationIPv4Address, 2886795266)
        self.assertEqual(ipaddress.ip_address(flow.destinationIPv4Address),
                         ipaddress.ip_address("172.17.0.2"))
        self.assertEqual(flow.protocolIdentifier, 6)  # TCP
        self.assertEqual(flow.sourceTransportPort, 443)
        self.assertEqual(flow.destinationTransportPort, 57766)
        self.assertEqual(flow.tcpControlBits, 0x1b)

        flow = p.export.flows[17]  # IPv6 flow
        self.assertEqual(flow.protocolIdentifier, 17)  # UDP
        self.assertEqual(flow.sourceIPv6Address, 0xfde66f14e0f196090000affeaffeaffe)
        self.assertEqual(ipaddress.ip_address(flow.sourceIPv6Address),  # Docker ULA
                         ipaddress.ip_address("fde6:6f14:e0f1:9609:0:affe:affe:affe"))

    def test_ipfix_contents_ether(self):
        """
        IPFIX content tests based on exports with the softflowd "-T ether" flag, meaning that layer 2
        is included in the export, like MAC addresses.
        :return:
        """
        pkts, _, _ = send_recv_packets([PACKET_IPFIX_TEMPLATE_ETHER, PACKET_IPFIX_ETHER])
        self.assertEqual(len(pkts), 2)
        p = pkts[0]

        # Inspect contents of specific flows
        flow = p.export.flows[0]
        self.assertEqual(flow.meteringProcessId, 9)
        self.assertEqual(flow.selectorAlgorithm, 1)
        self.assertEqual(flow.systemInitTimeMilliseconds, 759538800000)

        flow = p.export.flows[1]
        self.assertEqual(flow.destinationIPv4Address, 2886795266)
        self.assertTrue(hasattr(flow, "sourceMacAddress"))
        self.assertTrue(hasattr(flow, "postDestinationMacAddress"))
        self.assertEqual(flow.sourceMacAddress, 0x123456affefe)
        self.assertEqual(flow.postDestinationMacAddress, 0xaffeaffeaffe)
