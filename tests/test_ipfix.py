#!/usr/bin/env python3

"""
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.

Copyright 2016-2020 Dominik Pataky <dev@bitkeks.eu>
Licensed under MIT License. See LICENSE.
"""
# TODO: tests with 500 packets fail with delay=0. Probably a problem with UDP sockets buffer

import ipaddress
import unittest

from tests.lib import *


# Example export for IPFIX (v10) with 4 templates, 1 option template and 8 data flow sets
PACKET_IPFIX_TEMPLATE = "000a05205e8465fd0000001300000000000200400400000e00080004000c00040016000400150004" \
                        "0001000400020004000a0004000e000400070002000b00020004000100060001003c000100050001" \
                        "000200340401000b00080004000c000400160004001500040001000400020004000a0004000e0004" \
                        "00200002003c000100050001000200400800000e001b0010001c0010001600040015000400010004" \
                        "00020004000a0004000e000400070002000b00020004000100060001003c00010005000100020034" \
                        "0801000b001b0010001c001000160004001500040001000400020004000a0004000e0004008b0002" \
                        "003c0001000500010003001e010000050001008f000400a000080131000401320004013000020100" \
                        "001a00000a5900000171352e67210000000100000000000104000054976500dfac110002ff7ed688" \
                        "ff7ed73a000015c70000000d000000000000000001bbe1a6061b0400ac110002976500dfff7ed688" \
                        "ff7ed73a0000074f000000130000000000000000e1a601bb061f04000401004cac110002ac110001" \
                        "ff7db9e0ff7dc1d0000000fc00000003000000000000000008000400ac110001ac110002ff7db9e0" \
                        "ff7dc1d0000000fc0000000300000000000000000000040008010220fde66f14e0f1960900000242" \
                        "ac110002ff0200000000000000000001ff110001ff7dfad6ff7e0e95000001b00000000600000000" \
                        "0000000087000600fde66f14e0f1960900000242ac110002fde66f14e0f196090000000000000001" \
                        "ff7e567fff7e664a0000020800000005000000000000000080000600fde66f14e0f1960900000000" \
                        "00000001fde66f14e0f1960900000242ac110002ff7e567fff7e664a000002080000000500000000" \
                        "0000000081000600fe800000000000000042aafffe73bbfafde66f14e0f1960900000242ac110002" \
                        "ff7e6aaaff7e6aaa0000004800000001000000000000000087000600fde66f14e0f1960900000242" \
                        "ac110002fe800000000000000042aafffe73bbfaff7e6aaaff7e6aaa000000400000000100000000" \
                        "0000000088000600fe800000000000000042acfffe110002fe800000000000000042aafffe73bbfa" \
                        "ff7e7eaaff7e7eaa0000004800000001000000000000000087000600fe800000000000000042aaff" \
                        "fe73bbfafe800000000000000042acfffe110002ff7e7eaaff7e7eaa000000400000000100000000" \
                        "0000000088000600fe800000000000000042aafffe73bbfafe800000000000000042acfffe110002" \
                        "ff7e92aaff7e92aa0000004800000001000000000000000087000600fe800000000000000042acff" \
                        "fe110002fe800000000000000042aafffe73bbfaff7e92aaff7e92aa000000400000000100000000" \
                        "000000008800060008000044fde66f14e0f1960900000242ac110002fd41b7143f86000000000000" \
                        "00000001ff7ec2a0ff7ec2a00000004a000000010000000000000000d20100351100060004000054" \
                        "ac1100027f000001ff7ed62eff7ed68700000036000000010000000000000000c496003511000400" \
                        "7f000001ac110002ff7ed62eff7ed687000000760000000100000000000000000035c49611000400" \
                        "08000044fde66f14e0f1960900000242ac110002fd41b7143f8600000000000000000001ff7ef359" \
                        "ff7ef3590000004a000000010000000000000000b1e700351100060004000054ac1100027f000001" \
                        "ff7f06e4ff7f06e800000036000000010000000000000000a8f90035110004007f000001ac110002" \
                        "ff7f06e4ff7f06e8000000a60000000100000000000000000035a8f911000400"

# Example export for IPFIX with two data sets
PACKET_IPFIX = "000a00d05e8465fd00000016000000000801007cfe800000000000000042acfffe110002fde66f14" \
               "e0f196090000000000000001ff7f0755ff7f07550000004800000001000000000000000087000600" \
               "fde66f14e0f196090000000000000001fe800000000000000042acfffe110002ff7f0755ff7f0755" \
               "000000400000000100000000000000008800060008000044fde66f14e0f1960900000242ac110002" \
               "2a044e42020000000000000000000223ff7f06e9ff7f22d500000140000000040000000000000000" \
               "e54c01bb06020600"


class TestFlowExportIPFIX(unittest.TestCase):
    """Test IPFIX packet parsing
    """
    def test_recv_ipfix_packet(self):
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

        # Inspect contents of specific flows
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

        flow = p.export.flows[17]  # IPv6 flow
        self.assertEqual(flow.protocolIdentifier, 17)  # UDP
        self.assertEqual(flow.sourceIPv6Address, 337491164212692683663430561043420610562)
        self.assertEqual(ipaddress.ip_address(flow.sourceIPv6Address),  # Docker ULA
                         ipaddress.ip_address("fde6:6f14:e0f1:9609:0:242:ac11:2"))

        # send template and multiple export packets
        pkts, _, _ = send_recv_packets([PACKET_IPFIX, PACKET_IPFIX_TEMPLATE, PACKET_IPFIX])
        self.assertEqual(len(pkts), 3)
        self.assertEqual(pkts[0].export.header.version, 10)

        # check amount of flows across all packets
        total_flows = 0
        for packet in pkts:
            total_flows += len(packet.export.flows)
        self.assertEqual(total_flows, 2 + 1 + (1 + 2 + 2 + 9 + 1 + 2 + 1 + 2) + 2 + 1)
