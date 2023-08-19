#!/usr/bin/env python3

"""
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.
Reference: https://tools.ietf.org/html/rfc7011

Copyright 2016-2020 Dominik Pataky <software+pynetflow@dpataky.eu>
Licensed under MIT License. See LICENSE.
"""
import functools
import struct
from collections import namedtuple
from typing import Optional, Union, List, Dict

FieldType = namedtuple("FieldType", ["id", "name", "type"])
DataType = namedtuple("DataType", ["type", "unpack_format"])
TemplateField = namedtuple("TemplateField", ["id", "length"])
TemplateFieldEnterprise = namedtuple("TemplateFieldEnterprise", ["id", "length", "enterprise_number"])


class IPFIXFieldTypes:
    # Source: https://www.iana.org/assignments/ipfix/ipfix-information-elements.csv
    iana_field_types = [
        (0, "Reserved", ""),
        (1, "octetDeltaCount", "unsigned64"),
        (2, "packetDeltaCount", "unsigned64"),
        (3, "deltaFlowCount", "unsigned64"),
        (4, "protocolIdentifier", "unsigned8"),
        (5, "ipClassOfService", "unsigned8"),
        (6, "tcpControlBits", "unsigned16"),
        (7, "sourceTransportPort", "unsigned16"),
        (8, "sourceIPv4Address", "ipv4Address"),
        (9, "sourceIPv4PrefixLength", "unsigned8"),
        (10, "ingressInterface", "unsigned32"),
        (11, "destinationTransportPort", "unsigned16"),
        (12, "destinationIPv4Address", "ipv4Address"),
        (13, "destinationIPv4PrefixLength", "unsigned8"),
        (14, "egressInterface", "unsigned32"),
        (15, "ipNextHopIPv4Address", "ipv4Address"),
        (16, "bgpSourceAsNumber", "unsigned32"),
        (17, "bgpDestinationAsNumber", "unsigned32"),
        (18, "bgpNextHopIPv4Address", "ipv4Address"),
        (19, "postMCastPacketDeltaCount", "unsigned64"),
        (20, "postMCastOctetDeltaCount", "unsigned64"),
        (21, "flowEndSysUpTime", "unsigned32"),
        (22, "flowStartSysUpTime", "unsigned32"),
        (23, "postOctetDeltaCount", "unsigned64"),
        (24, "postPacketDeltaCount", "unsigned64"),
        (25, "minimumIpTotalLength", "unsigned64"),
        (26, "maximumIpTotalLength", "unsigned64"),
        (27, "sourceIPv6Address", "ipv6Address"),
        (28, "destinationIPv6Address", "ipv6Address"),
        (29, "sourceIPv6PrefixLength", "unsigned8"),
        (30, "destinationIPv6PrefixLength", "unsigned8"),
        (31, "flowLabelIPv6", "unsigned32"),
        (32, "icmpTypeCodeIPv4", "unsigned16"),
        (33, "igmpType", "unsigned8"),
        (34, "samplingInterval", "unsigned32"),
        (35, "samplingAlgorithm", "unsigned8"),
        (36, "flowActiveTimeout", "unsigned16"),
        (37, "flowIdleTimeout", "unsigned16"),
        (38, "engineType", "unsigned8"),
        (39, "engineId", "unsigned8"),
        (40, "exportedOctetTotalCount", "unsigned64"),
        (41, "exportedMessageTotalCount", "unsigned64"),
        (42, "exportedFlowRecordTotalCount", "unsigned64"),
        (43, "ipv4RouterSc", "ipv4Address"),
        (44, "sourceIPv4Prefix", "ipv4Address"),
        (45, "destinationIPv4Prefix", "ipv4Address"),
        (46, "mplsTopLabelType", "unsigned8"),
        (47, "mplsTopLabelIPv4Address", "ipv4Address"),
        (48, "samplerId", "unsigned8"),
        (49, "samplerMode", "unsigned8"),
        (50, "samplerRandomInterval", "unsigned32"),
        (51, "classId", "unsigned8"),
        (52, "minimumTTL", "unsigned8"),
        (53, "maximumTTL", "unsigned8"),
        (54, "fragmentIdentification", "unsigned32"),
        (55, "postIpClassOfService", "unsigned8"),
        (56, "sourceMacAddress", "macAddress"),
        (57, "postDestinationMacAddress", "macAddress"),
        (58, "vlanId", "unsigned16"),
        (59, "postVlanId", "unsigned16"),
        (60, "ipVersion", "unsigned8"),
        (61, "flowDirection", "unsigned8"),
        (62, "ipNextHopIPv6Address", "ipv6Address"),
        (63, "bgpNextHopIPv6Address", "ipv6Address"),
        (64, "ipv6ExtensionHeaders", "unsigned32"),
        (70, "mplsTopLabelStackSection", "octetArray"),
        (71, "mplsLabelStackSection2", "octetArray"),
        (72, "mplsLabelStackSection3", "octetArray"),
        (73, "mplsLabelStackSection4", "octetArray"),
        (74, "mplsLabelStackSection5", "octetArray"),
        (75, "mplsLabelStackSection6", "octetArray"),
        (76, "mplsLabelStackSection7", "octetArray"),
        (77, "mplsLabelStackSection8", "octetArray"),
        (78, "mplsLabelStackSection9", "octetArray"),
        (79, "mplsLabelStackSection10", "octetArray"),
        (80, "destinationMacAddress", "macAddress"),
        (81, "postSourceMacAddress", "macAddress"),
        (82, "interfaceName", "string"),
        (83, "interfaceDescription", "string"),
        (84, "samplerName", "string"),
        (85, "octetTotalCount", "unsigned64"),
        (86, "packetTotalCount", "unsigned64"),
        (87, "flagsAndSamplerId", "unsigned32"),
        (88, "fragmentOffset", "unsigned16"),
        (89, "forwardingStatus", "unsigned8"),
        (90, "mplsVpnRouteDistinguisher", "octetArray"),
        (91, "mplsTopLabelPrefixLength", "unsigned8"),
        (92, "srcTrafficIndex", "unsigned32"),
        (93, "dstTrafficIndex", "unsigned32"),
        (94, "applicationDescription", "string"),
        (95, "applicationId", "octetArray"),
        (96, "applicationName", "string"),
        (97, "Assigned for NetFlow v9 compatibility", ""),
        (98, "postIpDiffServCodePoint", "unsigned8"),
        (99, "multicastReplicationFactor", "unsigned32"),
        (100, "className", "string"),
        (101, "classificationEngineId", "unsigned8"),
        (102, "layer2packetSectionOffset", "unsigned16"),
        (103, "layer2packetSectionSize", "unsigned16"),
        (104, "layer2packetSectionData", "octetArray"),
        (128, "bgpNextAdjacentAsNumber", "unsigned32"),
        (129, "bgpPrevAdjacentAsNumber", "unsigned32"),
        (130, "exporterIPv4Address", "ipv4Address"),
        (131, "exporterIPv6Address", "ipv6Address"),
        (132, "droppedOctetDeltaCount", "unsigned64"),
        (133, "droppedPacketDeltaCount", "unsigned64"),
        (134, "droppedOctetTotalCount", "unsigned64"),
        (135, "droppedPacketTotalCount", "unsigned64"),
        (136, "flowEndReason", "unsigned8"),
        (137, "commonPropertiesId", "unsigned64"),
        (138, "observationPointId", "unsigned64"),
        (139, "icmpTypeCodeIPv6", "unsigned16"),
        (140, "mplsTopLabelIPv6Address", "ipv6Address"),
        (141, "lineCardId", "unsigned32"),
        (142, "portId", "unsigned32"),
        (143, "meteringProcessId", "unsigned32"),
        (144, "exportingProcessId", "unsigned32"),
        (145, "templateId", "unsigned16"),
        (146, "wlanChannelId", "unsigned8"),
        (147, "wlanSSID", "string"),
        (148, "flowId", "unsigned64"),
        (149, "observationDomainId", "unsigned32"),
        (150, "flowStartSeconds", "dateTimeSeconds"),
        (151, "flowEndSeconds", "dateTimeSeconds"),
        (152, "flowStartMilliseconds", "dateTimeMilliseconds"),
        (153, "flowEndMilliseconds", "dateTimeMilliseconds"),
        (154, "flowStartMicroseconds", "dateTimeMicroseconds"),
        (155, "flowEndMicroseconds", "dateTimeMicroseconds"),
        (156, "flowStartNanoseconds", "dateTimeNanoseconds"),
        (157, "flowEndNanoseconds", "dateTimeNanoseconds"),
        (158, "flowStartDeltaMicroseconds", "unsigned32"),
        (159, "flowEndDeltaMicroseconds", "unsigned32"),
        (160, "systemInitTimeMilliseconds", "dateTimeMilliseconds"),
        (161, "flowDurationMilliseconds", "unsigned32"),
        (162, "flowDurationMicroseconds", "unsigned32"),
        (163, "observedFlowTotalCount", "unsigned64"),
        (164, "ignoredPacketTotalCount", "unsigned64"),
        (165, "ignoredOctetTotalCount", "unsigned64"),
        (166, "notSentFlowTotalCount", "unsigned64"),
        (167, "notSentPacketTotalCount", "unsigned64"),
        (168, "notSentOctetTotalCount", "unsigned64"),
        (169, "destinationIPv6Prefix", "ipv6Address"),
        (170, "sourceIPv6Prefix", "ipv6Address"),
        (171, "postOctetTotalCount", "unsigned64"),
        (172, "postPacketTotalCount", "unsigned64"),
        (173, "flowKeyIndicator", "unsigned64"),
        (174, "postMCastPacketTotalCount", "unsigned64"),
        (175, "postMCastOctetTotalCount", "unsigned64"),
        (176, "icmpTypeIPv4", "unsigned8"),
        (177, "icmpCodeIPv4", "unsigned8"),
        (178, "icmpTypeIPv6", "unsigned8"),
        (179, "icmpCodeIPv6", "unsigned8"),
        (180, "udpSourcePort", "unsigned16"),
        (181, "udpDestinationPort", "unsigned16"),
        (182, "tcpSourcePort", "unsigned16"),
        (183, "tcpDestinationPort", "unsigned16"),
        (184, "tcpSequenceNumber", "unsigned32"),
        (185, "tcpAcknowledgementNumber", "unsigned32"),
        (186, "tcpWindowSize", "unsigned16"),
        (187, "tcpUrgentPointer", "unsigned16"),
        (188, "tcpHeaderLength", "unsigned8"),
        (189, "ipHeaderLength", "unsigned8"),
        (190, "totalLengthIPv4", "unsigned16"),
        (191, "payloadLengthIPv6", "unsigned16"),
        (192, "ipTTL", "unsigned8"),
        (193, "nextHeaderIPv6", "unsigned8"),
        (194, "mplsPayloadLength", "unsigned32"),
        (195, "ipDiffServCodePoint", "unsigned8"),
        (196, "ipPrecedence", "unsigned8"),
        (197, "fragmentFlags", "unsigned8"),
        (198, "octetDeltaSumOfSquares", "unsigned64"),
        (199, "octetTotalSumOfSquares", "unsigned64"),
        (200, "mplsTopLabelTTL", "unsigned8"),
        (201, "mplsLabelStackLength", "unsigned32"),
        (202, "mplsLabelStackDepth", "unsigned32"),
        (203, "mplsTopLabelExp", "unsigned8"),
        (204, "ipPayloadLength", "unsigned32"),
        (205, "udpMessageLength", "unsigned16"),
        (206, "isMulticast", "unsigned8"),
        (207, "ipv4IHL", "unsigned8"),
        (208, "ipv4Options", "unsigned32"),
        (209, "tcpOptions", "unsigned64"),
        (210, "paddingOctets", "octetArray"),
        (211, "collectorIPv4Address", "ipv4Address"),
        (212, "collectorIPv6Address", "ipv6Address"),
        (213, "exportInterface", "unsigned32"),
        (214, "exportProtocolVersion", "unsigned8"),
        (215, "exportTransportProtocol", "unsigned8"),
        (216, "collectorTransportPort", "unsigned16"),
        (217, "exporterTransportPort", "unsigned16"),
        (218, "tcpSynTotalCount", "unsigned64"),
        (219, "tcpFinTotalCount", "unsigned64"),
        (220, "tcpRstTotalCount", "unsigned64"),
        (221, "tcpPshTotalCount", "unsigned64"),
        (222, "tcpAckTotalCount", "unsigned64"),
        (223, "tcpUrgTotalCount", "unsigned64"),
        (224, "ipTotalLength", "unsigned64"),
        (225, "postNATSourceIPv4Address", "ipv4Address"),
        (226, "postNATDestinationIPv4Address", "ipv4Address"),
        (227, "postNAPTSourceTransportPort", "unsigned16"),
        (228, "postNAPTDestinationTransportPort", "unsigned16"),
        (229, "natOriginatingAddressRealm", "unsigned8"),
        (230, "natEvent", "unsigned8"),
        (231, "initiatorOctets", "unsigned64"),
        (232, "responderOctets", "unsigned64"),
        (233, "firewallEvent", "unsigned8"),
        (234, "ingressVRFID", "unsigned32"),
        (235, "egressVRFID", "unsigned32"),
        (236, "VRFname", "string"),
        (237, "postMplsTopLabelExp", "unsigned8"),
        (238, "tcpWindowScale", "unsigned16"),
        (239, "biflowDirection", "unsigned8"),
        (240, "ethernetHeaderLength", "unsigned8"),
        (241, "ethernetPayloadLength", "unsigned16"),
        (242, "ethernetTotalLength", "unsigned16"),
        (243, "dot1qVlanId", "unsigned16"),
        (244, "dot1qPriority", "unsigned8"),
        (245, "dot1qCustomerVlanId", "unsigned16"),
        (246, "dot1qCustomerPriority", "unsigned8"),
        (247, "metroEvcId", "string"),
        (248, "metroEvcType", "unsigned8"),
        (249, "pseudoWireId", "unsigned32"),
        (250, "pseudoWireType", "unsigned16"),
        (251, "pseudoWireControlWord", "unsigned32"),
        (252, "ingressPhysicalInterface", "unsigned32"),
        (253, "egressPhysicalInterface", "unsigned32"),
        (254, "postDot1qVlanId", "unsigned16"),
        (255, "postDot1qCustomerVlanId", "unsigned16"),
        (256, "ethernetType", "unsigned16"),
        (257, "postIpPrecedence", "unsigned8"),
        (258, "collectionTimeMilliseconds", "dateTimeMilliseconds"),
        (259, "exportSctpStreamId", "unsigned16"),
        (260, "maxExportSeconds", "dateTimeSeconds"),
        (261, "maxFlowEndSeconds", "dateTimeSeconds"),
        (262, "messageMD5Checksum", "octetArray"),
        (263, "messageScope", "unsigned8"),
        (264, "minExportSeconds", "dateTimeSeconds"),
        (265, "minFlowStartSeconds", "dateTimeSeconds"),
        (266, "opaqueOctets", "octetArray"),
        (267, "sessionScope", "unsigned8"),
        (268, "maxFlowEndMicroseconds", "dateTimeMicroseconds"),
        (269, "maxFlowEndMilliseconds", "dateTimeMilliseconds"),
        (270, "maxFlowEndNanoseconds", "dateTimeNanoseconds"),
        (271, "minFlowStartMicroseconds", "dateTimeMicroseconds"),
        (272, "minFlowStartMilliseconds", "dateTimeMilliseconds"),
        (273, "minFlowStartNanoseconds", "dateTimeNanoseconds"),
        (274, "collectorCertificate", "octetArray"),
        (275, "exporterCertificate", "octetArray"),
        (276, "dataRecordsReliability", "boolean"),
        (277, "observationPointType", "unsigned8"),
        (278, "newConnectionDeltaCount", "unsigned32"),
        (279, "connectionSumDurationSeconds", "unsigned64"),
        (280, "connectionTransactionId", "unsigned64"),
        (281, "postNATSourceIPv6Address", "ipv6Address"),
        (282, "postNATDestinationIPv6Address", "ipv6Address"),
        (283, "natPoolId", "unsigned32"),
        (284, "natPoolName", "string"),
        (285, "anonymizationFlags", "unsigned16"),
        (286, "anonymizationTechnique", "unsigned16"),
        (287, "informationElementIndex", "unsigned16"),
        (288, "p2pTechnology", "string"),
        (289, "tunnelTechnology", "string"),
        (290, "encryptedTechnology", "string"),
        (291, "basicList", "basicList"),
        (292, "subTemplateList", "subTemplateList"),
        (293, "subTemplateMultiList", "subTemplateMultiList"),
        (294, "bgpValidityState", "unsigned8"),
        (295, "IPSecSPI", "unsigned32"),
        (296, "greKey", "unsigned32"),
        (297, "natType", "unsigned8"),
        (298, "initiatorPackets", "unsigned64"),
        (299, "responderPackets", "unsigned64"),
        (300, "observationDomainName", "string"),
        (301, "selectionSequenceId", "unsigned64"),
        (302, "selectorId", "unsigned64"),
        (303, "informationElementId", "unsigned16"),
        (304, "selectorAlgorithm", "unsigned16"),
        (305, "samplingPacketInterval", "unsigned32"),
        (306, "samplingPacketSpace", "unsigned32"),
        (307, "samplingTimeInterval", "unsigned32"),
        (308, "samplingTimeSpace", "unsigned32"),
        (309, "samplingSize", "unsigned32"),
        (310, "samplingPopulation", "unsigned32"),
        (311, "samplingProbability", "float64"),
        (312, "dataLinkFrameSize", "unsigned16"),
        (313, "ipHeaderPacketSection", "octetArray"),
        (314, "ipPayloadPacketSection", "octetArray"),
        (315, "dataLinkFrameSection", "octetArray"),
        (316, "mplsLabelStackSection", "octetArray"),
        (317, "mplsPayloadPacketSection", "octetArray"),
        (318, "selectorIdTotalPktsObserved", "unsigned64"),
        (319, "selectorIdTotalPktsSelected", "unsigned64"),
        (320, "absoluteError", "float64"),
        (321, "relativeError", "float64"),
        (322, "observationTimeSeconds", "dateTimeSeconds"),
        (323, "observationTimeMilliseconds", "dateTimeMilliseconds"),
        (324, "observationTimeMicroseconds", "dateTimeMicroseconds"),
        (325, "observationTimeNanoseconds", "dateTimeNanoseconds"),
        (326, "digestHashValue", "unsigned64"),
        (327, "hashIPPayloadOffset", "unsigned64"),
        (328, "hashIPPayloadSize", "unsigned64"),
        (329, "hashOutputRangeMin", "unsigned64"),
        (330, "hashOutputRangeMax", "unsigned64"),
        (331, "hashSelectedRangeMin", "unsigned64"),
        (332, "hashSelectedRangeMax", "unsigned64"),
        (333, "hashDigestOutput", "boolean"),
        (334, "hashInitialiserValue", "unsigned64"),
        (335, "selectorName", "string"),
        (336, "upperCILimit", "float64"),
        (337, "lowerCILimit", "float64"),
        (338, "confidenceLevel", "float64"),
        (339, "informationElementDataType", "unsigned8"),
        (340, "informationElementDescription", "string"),
        (341, "informationElementName", "string"),
        (342, "informationElementRangeBegin", "unsigned64"),
        (343, "informationElementRangeEnd", "unsigned64"),
        (344, "informationElementSemantics", "unsigned8"),
        (345, "informationElementUnits", "unsigned16"),
        (346, "privateEnterpriseNumber", "unsigned32"),
        (347, "virtualStationInterfaceId", "octetArray"),
        (348, "virtualStationInterfaceName", "string"),
        (349, "virtualStationUUID", "octetArray"),
        (350, "virtualStationName", "string"),
        (351, "layer2SegmentId", "unsigned64"),
        (352, "layer2OctetDeltaCount", "unsigned64"),
        (353, "layer2OctetTotalCount", "unsigned64"),
        (354, "ingressUnicastPacketTotalCount", "unsigned64"),
        (355, "ingressMulticastPacketTotalCount", "unsigned64"),
        (356, "ingressBroadcastPacketTotalCount", "unsigned64"),
        (357, "egressUnicastPacketTotalCount", "unsigned64"),
        (358, "egressBroadcastPacketTotalCount", "unsigned64"),
        (359, "monitoringIntervalStartMilliSeconds", "dateTimeMilliseconds"),
        (360, "monitoringIntervalEndMilliSeconds", "dateTimeMilliseconds"),
        (361, "portRangeStart", "unsigned16"),
        (362, "portRangeEnd", "unsigned16"),
        (363, "portRangeStepSize", "unsigned16"),
        (364, "portRangeNumPorts", "unsigned16"),
        (365, "staMacAddress", "macAddress"),
        (366, "staIPv4Address", "ipv4Address"),
        (367, "wtpMacAddress", "macAddress"),
        (368, "ingressInterfaceType", "unsigned32"),
        (369, "egressInterfaceType", "unsigned32"),
        (370, "rtpSequenceNumber", "unsigned16"),
        (371, "userName", "string"),
        (372, "applicationCategoryName", "string"),
        (373, "applicationSubCategoryName", "string"),
        (374, "applicationGroupName", "string"),
        (375, "originalFlowsPresent", "unsigned64"),
        (376, "originalFlowsInitiated", "unsigned64"),
        (377, "originalFlowsCompleted", "unsigned64"),
        (378, "distinctCountOfSourceIPAddress", "unsigned64"),
        (379, "distinctCountOfDestinationIPAddress", "unsigned64"),
        (380, "distinctCountOfSourceIPv4Address", "unsigned32"),
        (381, "distinctCountOfDestinationIPv4Address", "unsigned32"),
        (382, "distinctCountOfSourceIPv6Address", "unsigned64"),
        (383, "distinctCountOfDestinationIPv6Address", "unsigned64"),
        (384, "valueDistributionMethod", "unsigned8"),
        (385, "rfc3550JitterMilliseconds", "unsigned32"),
        (386, "rfc3550JitterMicroseconds", "unsigned32"),
        (387, "rfc3550JitterNanoseconds", "unsigned32"),
        (388, "dot1qDEI", "boolean"),
        (389, "dot1qCustomerDEI", "boolean"),
        (390, "flowSelectorAlgorithm", "unsigned16"),
        (391, "flowSelectedOctetDeltaCount", "unsigned64"),
        (392, "flowSelectedPacketDeltaCount", "unsigned64"),
        (393, "flowSelectedFlowDeltaCount", "unsigned64"),
        (394, "selectorIDTotalFlowsObserved", "unsigned64"),
        (395, "selectorIDTotalFlowsSelected", "unsigned64"),
        (396, "samplingFlowInterval", "unsigned64"),
        (397, "samplingFlowSpacing", "unsigned64"),
        (398, "flowSamplingTimeInterval", "unsigned64"),
        (399, "flowSamplingTimeSpacing", "unsigned64"),
        (400, "hashFlowDomain", "unsigned16"),
        (401, "transportOctetDeltaCount", "unsigned64"),
        (402, "transportPacketDeltaCount", "unsigned64"),
        (403, "originalExporterIPv4Address", "ipv4Address"),
        (404, "originalExporterIPv6Address", "ipv6Address"),
        (405, "originalObservationDomainId", "unsigned32"),
        (406, "intermediateProcessId", "unsigned32"),
        (407, "ignoredDataRecordTotalCount", "unsigned64"),
        (408, "dataLinkFrameType", "unsigned16"),
        (409, "sectionOffset", "unsigned16"),
        (410, "sectionExportedOctets", "unsigned16"),
        (411, "dot1qServiceInstanceTag", "octetArray"),
        (412, "dot1qServiceInstanceId", "unsigned32"),
        (413, "dot1qServiceInstancePriority", "unsigned8"),
        (414, "dot1qCustomerSourceMacAddress", "macAddress"),
        (415, "dot1qCustomerDestinationMacAddress", "macAddress"),
        (416, "", ""),
        (417, "postLayer2OctetDeltaCount", "unsigned64"),
        (418, "postMCastLayer2OctetDeltaCount", "unsigned64"),
        (419, "", ""),
        (420, "postLayer2OctetTotalCount", "unsigned64"),
        (421, "postMCastLayer2OctetTotalCount", "unsigned64"),
        (422, "minimumLayer2TotalLength", "unsigned64"),
        (423, "maximumLayer2TotalLength", "unsigned64"),
        (424, "droppedLayer2OctetDeltaCount", "unsigned64"),
        (425, "droppedLayer2OctetTotalCount", "unsigned64"),
        (426, "ignoredLayer2OctetTotalCount", "unsigned64"),
        (427, "notSentLayer2OctetTotalCount", "unsigned64"),
        (428, "layer2OctetDeltaSumOfSquares", "unsigned64"),
        (429, "layer2OctetTotalSumOfSquares", "unsigned64"),
        (430, "layer2FrameDeltaCount", "unsigned64"),
        (431, "layer2FrameTotalCount", "unsigned64"),
        (432, "pseudoWireDestinationIPv4Address", "ipv4Address"),
        (433, "ignoredLayer2FrameTotalCount", "unsigned64"),
        (434, "mibObjectValueInteger", "signed32"),
        (435, "mibObjectValueOctetString", "octetArray"),
        (436, "mibObjectValueOID", "octetArray"),
        (437, "mibObjectValueBits", "octetArray"),
        (438, "mibObjectValueIPAddress", "ipv4Address"),
        (439, "mibObjectValueCounter", "unsigned64"),
        (440, "mibObjectValueGauge", "unsigned32"),
        (441, "mibObjectValueTimeTicks", "unsigned32"),
        (442, "mibObjectValueUnsigned", "unsigned32"),
        (443, "mibObjectValueTable", "subTemplateList"),
        (444, "mibObjectValueRow", "subTemplateList"),
        (445, "mibObjectIdentifier", "octetArray"),
        (446, "mibSubIdentifier", "unsigned32"),
        (447, "mibIndexIndicator", "unsigned64"),
        (448, "mibCaptureTimeSemantics", "unsigned8"),
        (449, "mibContextEngineID", "octetArray"),
        (450, "mibContextName", "string"),
        (451, "mibObjectName", "string"),
        (452, "mibObjectDescription", "string"),
        (453, "mibObjectSyntax", "string"),
        (454, "mibModuleName", "string"),
        (455, "mobileIMSI", "string"),
        (456, "mobileMSISDN", "string"),
        (457, "httpStatusCode", "unsigned16"),
        (458, "sourceTransportPortsLimit", "unsigned16"),
        (459, "httpRequestMethod", "string"),
        (460, "httpRequestHost", "string"),
        (461, "httpRequestTarget", "string"),
        (462, "httpMessageVersion", "string"),
        (463, "natInstanceID", "unsigned32"),
        (464, "internalAddressRealm", "octetArray"),
        (465, "externalAddressRealm", "octetArray"),
        (466, "natQuotaExceededEvent", "unsigned32"),
        (467, "natThresholdEvent", "unsigned32"),
        (468, "httpUserAgent", "string"),
        (469, "httpContentType", "string"),
        (470, "httpReasonPhrase", "string"),
        (471, "maxSessionEntries", "unsigned32"),
        (472, "maxBIBEntries", "unsigned32"),
        (473, "maxEntriesPerUser", "unsigned32"),
        (474, "maxSubscribers", "unsigned32"),
        (475, "maxFragmentsPendingReassembly", "unsigned32"),
        (476, "addressPoolHighThreshold", "unsigned32"),
        (477, "addressPoolLowThreshold", "unsigned32"),
        (478, "addressPortMappingHighThreshold", "unsigned32"),
        (479, "addressPortMappingLowThreshold", "unsigned32"),
        (480, "addressPortMappingPerUserHighThreshold", "unsigned32"),
        (481, "globalAddressMappingHighThreshold", "unsigned32"),
        (482, "vpnIdentifier", "octetArray"),
        (483, "bgpCommunity", "unsigned32"),
        (484, "bgpSourceCommunityList", "basicList"),
        (485, "bgpDestinationCommunityList", "basicList"),
        (486, "bgpExtendedCommunity", "octetArray"),
        (487, "bgpSourceExtendedCommunityList", "basicList"),
        (488, "bgpDestinationExtendedCommunityList", "basicList"),
        (489, "bgpLargeCommunity", "octetArray"),
        (490, "bgpSourceLargeCommunityList", "basicList"),
        (491, "bgpDestinationLargeCommunityList", "basicList"),
    ]

    @classmethod
    @functools.lru_cache(maxsize=128)
    def by_id(cls, id_: int) -> Optional[FieldType]:
        for item in cls.iana_field_types:
            if item[0] == id_:
                return FieldType(*item)
        return None

    @classmethod
    @functools.lru_cache(maxsize=128)
    def by_name(cls, key: str) -> Optional[FieldType]:
        for item in cls.iana_field_types:
            if item[1] == key:
                return FieldType(*item)
        return None

    @classmethod
    @functools.lru_cache(maxsize=128)
    def get_type_unpack(cls, key: Union[int, str]) -> Optional[DataType]:
        """
        This method covers the mapping from a field type to a struct.unpack format string.
        BLOCKED: due to Reduced-Size Encoding, fields may be exported with a smaller length than defined in
        the standard. Because of this mismatch, the parser in `IPFIXDataRecord.__init__` cannot use this method.
        :param key:
        :return:
        """
        item = None
        if type(key) is int:
            item = cls.by_id(key)
        elif type(key) is str:
            item = cls.by_name(key)
        if not item:
            return None
        return IPFIXDataTypes.by_name(item.type)


class IPFIXDataTypes:
    # Source: https://www.iana.org/assignments/ipfix/ipfix-information-element-data-types.csv
    # Reference: https://tools.ietf.org/html/rfc7011
    iana_data_types = [
        ("octetArray", None),  # has no encoding rules; it represents a raw array of zero or more octets
        ("unsigned8", "B"),
        ("unsigned16", "H"),
        ("unsigned32", "I"),
        ("unsigned64", "Q"),
        ("signed8", "b"),
        ("signed16", "h"),
        ("signed32", "i"),
        ("signed64", "q"),
        ("float32", "f"),
        ("float64", "d"),
        ("boolean", "?"),  # encoded as a single-octet integer [..], with the value 1 for true and value 2 for false.
        ("macAddress", "6s"),
        ("string", None),  # represents a finite-length string of valid characters of the Unicode encoding set
        ("dateTimeSeconds", "I"),
        ("dateTimeMilliseconds", "Q"),
        ("dateTimeMicroseconds", "8s"),  # This field is made up of two unsigned 32-bit integers
        ("dateTimeNanoseconds", "8s"),  # same as above
        ("ipv4Address", "4s"),
        ("ipv6Address", "16s"),

        # To be implemented
        # ("basicList", "x"),
        # ("subTemplateList", "x"),
        # ("subTemplateMultiList", "x"),
    ]

    @classmethod
    @functools.lru_cache(maxsize=128)
    def by_name(cls, key: str) -> Optional[DataType]:
        """
        Get DataType by name if found, else None.
        :param key:
        :return:
        """
        for t in cls.iana_data_types:
            if t[0] == key:
                return DataType(*t)
        return None

    @classmethod
    def is_signed(cls, dt: Union[DataType, str]) -> bool:
        """
        Check if a data type is meant to be a signed integer.
        :param dt:
        :return:
        """
        fields = ["signed8", "signed16", "signed32", "signed64"]
        if type(dt) is DataType:
            return dt.type in fields
        return dt in fields

    @classmethod
    def is_float(cls, dt: Union[DataType, str]) -> bool:
        """
        Check if data type is meant to be a float.
        :param dt:
        :return:
        """
        fields = ["float32", "float64"]
        if type(dt) is DataType:
            return dt.type in fields
        return dt in fields

    @classmethod
    def is_bytes(cls, dt: Union[DataType, str]) -> bool:
        """
        Check if a data type is meant to be parsed as bytes.
        :param dt:
        :return:
        """
        fields = ["octetArray", "string",
                  "macAddress", "ipv4Address", "ipv6Address",
                  "dateTimeMicroseconds", "dateTimeNanoseconds"]
        if type(dt) is DataType:
            return dt.type in fields
        return dt in fields

    @classmethod
    def to_fitting_object(cls, field):
        """
        Could implement conversion to IPv4Address etc.
        :param field:
        :return:
        """
        pass


class IPFIXMalformedRecord(Exception):
    pass


class IPFIXRFCError(Exception):
    pass


class IPFIXMalformedPacket(Exception):
    pass


class IPFIXTemplateError(Exception):
    pass


class IPFIXTemplateNotRecognized(KeyError):
    pass


class PaddingCalculationError(Exception):
    pass


class IPFIXHeader:
    """The header of the IPFIX export packet
    """
    size = 16

    def __init__(self, data):
        pack = struct.unpack('!HHIII', data)
        self.version = pack[0]
        self.length = pack[1]
        self.export_uptime = pack[2]
        self.sequence_number = pack[3]
        self.obervation_domain_id = pack[4]

    def to_dict(self):
        return self.__dict__


class IPFIXTemplateRecord:
    def __init__(self, data):
        pack = struct.unpack("!HH", data[:4])
        self.template_id = pack[0]  # range 256 to 65535
        self.field_count = pack[1]  # Number of fields in this Template Record

        offset = 4
        self.fields, offset_add = parse_fields(data[offset:], self.field_count)
        offset += offset_add
        if len(self.fields) != self.field_count:
            raise IPFIXMalformedRecord
        self._length = offset

    def get_length(self):
        return self._length

    def __repr__(self):
        return "<IPFIXTemplateRecord with {} fields>".format(len(self.fields))


class IPFIXOptionsTemplateRecord:
    def __init__(self, data):
        pack = struct.unpack("!HHH", data[:6])
        self.template_id = pack[0]  # range 256 to 65535
        self.field_count = pack[1]  # includes count of scope fields

        # A scope field count of N specifies that the first N Field Specifiers in
        # the Template Record are Scope Fields. The Scope Field Count MUST NOT be zero.
        self.scope_field_count = pack[2]

        offset = 6

        self.scope_fields, offset_add = parse_fields(data[offset:], self.scope_field_count)
        if len(self.scope_fields) != self.scope_field_count:
            raise IPFIXMalformedRecord
        offset += offset_add

        self.fields, offset_add = parse_fields(data[offset:], self.field_count - self.scope_field_count)
        if len(self.fields) + len(self.scope_fields) != self.field_count:
            raise IPFIXMalformedRecord
        offset += offset_add

        self._length = offset

    def get_length(self):
        return self._length

    def __repr__(self):
        return "<IPFIXOptionsTemplateRecord with {} scope fields and {} fields>".format(
            len(self.scope_fields), len(self.fields)
        )


class IPFIXDataRecord:
    """The IPFIX data record with fields and their value.
    The field types are identified by the corresponding template.
    In contrast to the NetFlow v9 implementation, this one does not use an extra class for the fields.
    """

    def __init__(self, data, template: List[Union[TemplateField, TemplateFieldEnterprise]]):
        self.fields = set()
        offset = 0
        unpacker = "!"
        discovered_fields = []

        # Iterate through all fields of this template and build the unpack format string
        # See https://www.iana.org/assignments/ipfix/ipfix.xhtml
        for index, field in enumerate(template):
            field_type_id = field.id
            field_length = field.length
            offset += field_length

            # Here, reduced-size encoding of fields blocks the usage of IPFIXFieldTypes.get_type_unpack.
            # See comment in IPFIXFieldTypes.get_type_unpack for more information.

            field_type = IPFIXFieldTypes.by_id(field_type_id)  # type: Optional[FieldType]
            if not field_type and type(field) is not TemplateFieldEnterprise:
                # This should break, since the exporter seems to use a field identifier
                # which is not standardized by IANA.
                raise NotImplementedError("Field type with ID {} is not implemented".format(field_type_id))

            datatype = field_type.type  # type: str
            discovered_fields.append((datatype, field_type_id))

            # Catch fields which are meant to be raw bytes and skip the rest
            if IPFIXDataTypes.is_bytes(datatype):
                unpacker += "{}s".format(field_length)
                continue

            # Go into int, uint, float types
            issigned = IPFIXDataTypes.is_signed(datatype)
            isfloat = IPFIXDataTypes.is_float(datatype)
            assert not (all([issigned, isfloat]))  # signed int and float are exclusive

            if field_length == 1:
                unpacker += "b" if issigned else "B"
            elif field_length == 2:
                unpacker += "h" if issigned else "H"
            elif field_length == 4:
                unpacker += "i" if issigned else "f" if isfloat else "I"
            elif field_length == 8:
                unpacker += "q" if issigned else "d" if isfloat else "Q"
            else:
                raise IPFIXTemplateError("Template field_length {} not handled in unpacker".format(field_length))

        # Finally, unpack the data byte stream according to format defined in iteration above
        pack = struct.unpack(unpacker, data[0:offset])

        # Iterate through template again, but taking the unpacked values this time
        for index, ((field_datatype, field_type_id), value) in enumerate(zip(discovered_fields, pack)):
            if type(value) is bytes:
                # Check if value is raw bytes, so no conversion happened in struct.unpack
                if field_datatype in ["string"]:
                    try:
                        value = value.decode()
                    except UnicodeDecodeError:
                        value = str(value)
                # TODO: handle octetArray (= does not have to be unicode encoded)
                elif field_datatype in ["boolean"]:
                    value = True if value == 1 else False  # 2 = false per RFC
                elif field_datatype in ["dateTimeMicroseconds", "dateTimeNanoseconds"]:
                    seconds = value[:4]
                    fraction = value[4:]
                    value = (int.from_bytes(seconds, "big"), int.from_bytes(fraction, "big"))
                else:
                    value = int.from_bytes(value, "big")
            # If not bytes, struct.unpack already did necessary conversions (int, float...),
            # value can be used as-is.
            self.fields.add((field_type_id, value))

        self._length = offset
        self.__dict__.update(self.data)

    def get_length(self):
        return self._length

    @property
    def data(self):
        return {
            IPFIXFieldTypes.by_id(key)[1]: value for (key, value) in self.fields
        }

    def __repr__(self):
        return "<IPFIXDataRecord with {} entries>".format(len(self.fields))


class IPFIXSet:
    """A set containing the set header and a collection of records (one of templates, options, data)
    """

    def __init__(self, data: bytes, templates):
        self.header = IPFIXSetHeader(data[0:IPFIXSetHeader.size])
        self.records = []
        self._templates = {}

        offset = IPFIXSetHeader.size  # fixed size

        if self.header.set_id == 2:  # template set
            while offset < self.header.length:  # length of whole set
                template_record = IPFIXTemplateRecord(data[offset:])
                self.records.append(template_record)
                if template_record.field_count == 0:
                    # Should not happen, since RFC says "one or more"
                    self._templates[template_record.template_id] = None
                else:
                    self._templates[template_record.template_id] = template_record.fields
                offset += template_record.get_length()

                # If the rest of the data is deemed to be too small for another
                # template record, check existence of padding
                if (
                        offset != self.header.length
                        and self.header.length - offset <= 16  # 16 is chosen as a guess
                        and rest_is_padding_zeroes(data[:self.header.length], offset)
                ):
                    # Rest should be padding zeroes
                    break

        elif self.header.set_id == 3:  # options template
            while offset < self.header.length:
                optionstemplate_record = IPFIXOptionsTemplateRecord(data[offset:])
                self.records.append(optionstemplate_record)
                if optionstemplate_record.field_count == 0:
                    self._templates[optionstemplate_record.template_id] = None
                else:
                    self._templates[optionstemplate_record.template_id] = \
                        optionstemplate_record.scope_fields + optionstemplate_record.fields
                offset += optionstemplate_record.get_length()

                # If the rest of the data is deemed to be too small for another
                # options template record, check existence of padding
                if (
                        offset != self.header.length
                        and self.header.length - offset <= 16  # 16 is chosen as a guess
                        and rest_is_padding_zeroes(data[:self.header.length], offset)
                ):
                    # Rest should be padding zeroes
                    break

        elif self.header.set_id >= 256:  # data set, set_id is template id
            # First, get the template behind the ID. Returns a list of fields or raises an exception
            template_fields = templates.get(
                self.header.set_id)  # type: List[Union[TemplateField, TemplateFieldEnterprise]]
            if not template_fields:
                raise IPFIXTemplateNotRecognized

            # All template fields have a known length. Add them all together to get the length of the data set.
            dataset_length = functools.reduce(lambda a, x: a + x.length, template_fields, 0)

            # This is the last possible offset value possible if there's no padding.
            # If there is padding, this value marks the beginning of the padding.
            # Two cases possible:
            # 1. No padding: then (4 + x * dataset_length) == self.header.length
            # 2. Padding: then (4 + x * dataset_length + p) == self.header.length,
            #    where p is the remaining length of padding zeroes. The modulo calculates p
            no_padding_last_offset = self.header.length - ((self.header.length - IPFIXSetHeader.size) % dataset_length)

            while offset < no_padding_last_offset:
                data_record = IPFIXDataRecord(data[offset:], template_fields)
                self.records.append(data_record)
                offset += data_record.get_length()

            # Safety check
            if (
                    offset != self.header.length
                    and not rest_is_padding_zeroes(data[:self.header.length], offset)
            ):
                raise PaddingCalculationError

        self._length = self.header.length

    def get_length(self):
        return self._length

    @property
    def is_template(self):
        return self.header.set_id in [2, 3]

    @property
    def is_data(self):
        return self.header.set_id >= 256

    @property
    def templates(self):
        return self._templates

    def __repr__(self):
        return "<IPFIXSet with set_id {} and {} records>".format(self.header.set_id, len(self.records))


class IPFIXSetHeader:
    """Header of a set (collection of records)
    """
    size = 4

    def __init__(self, data):
        pack = struct.unpack("!HH", data)

        # A value of 2 is reserved for Template Sets.
        # A value of 3 is reserved for Options Template Sets.  Values from 4
        # to 255 are reserved for future use.  Values 256 and above are used
        # for Data Sets.  The Set ID values of 0 and 1 are not used, for
        # historical reasons [RFC3954].
        self.set_id = pack[0]
        if self.set_id in [0, 1] + [i for i in range(4, 256)]:
            raise IPFIXRFCError("IPFIX set has forbidden ID {}".format(self.set_id))

        self.length = pack[1]  # Total length of the Set, in octets, including the Set Header

    def to_dict(self):
        return self.__dict__

    def __repr__(self):
        return "<IPFIXSetHeader with set_id {} and length {}>".format(self.set_id, self.length)


class IPFIXExportPacket:
    """IPFIX export packet with header, templates, options and data flowsets
    """

    def __init__(self, data: bytes, templates: Dict[int, list]):
        self.header = IPFIXHeader(data[:IPFIXHeader.size])
        self.sets = []
        self._contains_new_templates = False
        self._flows = []
        self._templates = templates

        offset = IPFIXHeader.size
        while offset < self.header.length:
            try:
                new_set = IPFIXSet(data[offset:], templates)
            except IPFIXTemplateNotRecognized:
                raise
            if new_set.is_template:
                self._contains_new_templates = True
                self._templates.update(new_set.templates)
                for template_id, template_fields in self._templates.items():
                    if template_fields is None:
                        # Template withdrawal
                        del self._templates[template_id]
            elif new_set.is_data:
                self._flows += new_set.records

            self.sets.append(new_set)
            offset += new_set.get_length()

        # Here all data should be processed and offset set to the length
        if offset != self.header.length:
            raise IPFIXMalformedPacket

    @property
    def contains_new_templates(self) -> bool:
        return self._contains_new_templates

    @property
    def flows(self):
        return self._flows

    @property
    def templates(self):
        return self._templates

    def __repr__(self):
        return "<IPFIXExportPacket with {} sets, exported at {}>".format(
            len(self.sets), self.header.export_uptime
        )


def parse_fields(data: bytes, count: int) -> (list, int):
    """
    Parse fields from a bytes stream, based on the count of fields.
    If the field is an enterprise field or not will be determinded in this function.
    :param data:
    :param count:
    :return: List of fields and the new offset.
    """
    offset = 0
    fields = []  # type: List[Union[TemplateField, TemplateFieldEnterprise]]
    for ctr in range(count):
        if (data[offset] & (1 << 7)) != 0:  # enterprise flag set. Bitwise AND checks bit only in the first byte/octet
            pack = struct.unpack("!HHI", data[offset:offset + 8])
            fields.append(
                TemplateFieldEnterprise(
                    id=(pack[0] & ~(1 << 15)),  # clear enterprise flag bit. Bitwise AND and INVERT work on two bytes
                    length=pack[1],  # field length
                    enterprise_number=pack[2]  # enterprise number
                )
            )
            offset += 8
        else:
            pack = struct.unpack("!HH", data[offset:offset + 4])
            fields.append(
                TemplateField(
                    id=pack[0],
                    length=pack[1]
                )
            )
            offset += 4
    return fields, offset


def rest_is_padding_zeroes(data: bytes, offset: int) -> bool:
    if offset <= len(data):
        # padding zeros, so rest of bytes must be summed to 0
        if sum(data[offset:]) != 0:
            return False
        return True

    # If offset > len(data) there is an error
    raise ValueError("netflow.ipfix.rest_is_padding_zeroes received a greater offset value than there is data")
