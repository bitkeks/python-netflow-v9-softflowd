#!/usr/bin/env python3

"""
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.
Reference: https://tools.ietf.org/html/rfc7011

Copyright 2016-2020 Dominik Pataky <dev@bitkeks.eu>
Licensed under MIT License. See LICENSE.
"""

import struct

# Source: https://www.iana.org/assignments/ipfix/ipfix-information-elements.csv
IPFIX_FIELD_TYPES = {
    0: "Reserved", 1: 'octetDeltaCount', 2: "packetDeltaCount", 3: "deltaFlowCount", 4: "protocolIdentifier",
    5: "ipClassOfService", 6: "tcpControlBits", 7: "sourceTransportPort", 8: "sourceIPv4Address",
    9: "sourceIPv4PrefixLength", 10: "ingressInterface", 11: "destinationTransportPort",
    12: "destinationIPv4Address", 13: "destinationIPv4PrefixLength", 14: "egressInterface",
    15: "ipNextHopIPv4Address", 16: "bgpSourceAsNumber", 17: "bgpDestinationAsNumber", 18: "bgpNextHopIPv4Address",
    19: "postMCastPacketDeltaCount", 20: "postMCastOctetDeltaCount", 21: "flowEndSysUpTime",
    22: "flowStartSysUpTime", 23: "postOctetDeltaCount", 24: "postPacketDeltaCount", 25: "minimumIpTotalLength",
    26: "maximumIpTotalLength", 27: "sourceIPv6Address", 28: "destinationIPv6Address",
    29: "sourceIPv6PrefixLength", 30: "destinationIPv6PrefixLength", 31: "flowLabelIPv6", 32: "icmpTypeCodeIPv4",
    33: "igmpType", 34: "samplingInterval", 35: "samplingAlgorithm", 36: "flowActiveTimeout",
    37: "flowIdleTimeout", 38: "engineType", 39: "engineId", 40: "exportedOctetTotalCount",
    41: "exportedMessageTotalCount", 42: "exportedFlowRecordTotalCount", 43: "ipv4RouterSc",
    44: "sourceIPv4Prefix", 45: "destinationIPv4Prefix", 46: "mplsTopLabelType", 47: "mplsTopLabelIPv4Address",
    48: "samplerId", 49: "samplerMode", 50: "samplerRandomInterval", 51: "classId", 52: "minimumTTL",
    53: "maximumTTL", 54: "fragmentIdentification", 55: "postIpClassOfService", 56: "sourceMacAddress",
    57: "postDestinationMacAddress", 58: "vlanId", 59: "postVlanId", 60: "ipVersion", 61: "flowDirection",
    62: "ipNextHopIPv6Address", 63: "bgpNextHopIPv6Address", 64: "ipv6ExtensionHeaders",
    70: "mplsTopLabelStackSection", 71: "mplsLabelStackSection2", 72: "mplsLabelStackSection3",
    73: "mplsLabelStackSection4", 74: "mplsLabelStackSection5", 75: "mplsLabelStackSection6",
    76: "mplsLabelStackSection7", 77: "mplsLabelStackSection8", 78: "mplsLabelStackSection9",
    79: "mplsLabelStackSection10", 80: "destinationMacAddress", 81: "postSourceMacAddress", 82: "interfaceName",
    83: "interfaceDescription", 84: "samplerName", 85: "octetTotalCount", 86: "packetTotalCount",
    87: "flagsAndSamplerId", 88: "fragmentOffset", 89: "forwardingStatus", 90: "mplsVpnRouteDistinguisher",
    91: "mplsTopLabelPrefixLength", 92: "srcTrafficIndex", 93: "dstTrafficIndex", 94: "applicationDescription",
    95: "applicationId", 96: "applicationName", 97: "Assigned for NetFlow v9 compatibility",
    98: "postIpDiffServCodePoint", 99: "multicastReplicationFactor", 100: "className",
    101: "classificationEngineId", 102: "layer2packetSectionOffset", 103: "layer2packetSectionSize",
    104: "layer2packetSectionData", 128: "bgpNextAdjacentAsNumber", 129: "bgpPrevAdjacentAsNumber",
    130: "exporterIPv4Address", 131: "exporterIPv6Address", 132: "droppedOctetDeltaCount",
    133: "droppedPacketDeltaCount", 134: "droppedOctetTotalCount", 135: "droppedPacketTotalCount",
    136: "flowEndReason", 137: "commonPropertiesId", 138: "observationPointId", 139: "icmpTypeCodeIPv6",
    140: "mplsTopLabelIPv6Address", 141: "lineCardId", 142: "portId", 143: "meteringProcessId",
    144: "exportingProcessId", 145: "templateId", 146: "wlanChannelId", 147: "wlanSSID", 148: "flowId",
    149: "observationDomainId", 150: "flowStartSeconds", 151: "flowEndSeconds", 152: "flowStartMilliseconds",
    153: "flowEndMilliseconds", 154: "flowStartMicroseconds", 155: "flowEndMicroseconds",
    156: "flowStartNanoseconds", 157: "flowEndNanoseconds", 158: "flowStartDeltaMicroseconds",
    159: "flowEndDeltaMicroseconds", 160: "systemInitTimeMilliseconds", 161: "flowDurationMilliseconds",
    162: "flowDurationMicroseconds", 163: "observedFlowTotalCount", 164: "ignoredPacketTotalCount",
    165: "ignoredOctetTotalCount", 166: "notSentFlowTotalCount", 167: "notSentPacketTotalCount",
    168: "notSentOctetTotalCount", 169: "destinationIPv6Prefix", 170: "sourceIPv6Prefix",
    171: "postOctetTotalCount", 172: "postPacketTotalCount", 173: "flowKeyIndicator",
    174: "postMCastPacketTotalCount", 175: "postMCastOctetTotalCount", 176: "icmpTypeIPv4", 177: "icmpCodeIPv4",
    178: "icmpTypeIPv6", 179: "icmpCodeIPv6", 180: "udpSourcePort", 181: "udpDestinationPort",
    182: "tcpSourcePort", 183: "tcpDestinationPort", 184: "tcpSequenceNumber", 185: "tcpAcknowledgementNumber",
    186: "tcpWindowSize", 187: "tcpUrgentPointer", 188: "tcpHeaderLength", 189: "ipHeaderLength",
    190: "totalLengthIPv4", 191: "payloadLengthIPv6", 192: "ipTTL", 193: "nextHeaderIPv6",
    194: "mplsPayloadLength", 195: "ipDiffServCodePoint", 196: "ipPrecedence", 197: "fragmentFlags",
    198: "octetDeltaSumOfSquares", 199: "octetTotalSumOfSquares", 200: "mplsTopLabelTTL",
    201: "mplsLabelStackLength", 202: "mplsLabelStackDepth", 203: "mplsTopLabelExp", 204: "ipPayloadLength",
    205: "udpMessageLength", 206: "isMulticast", 207: "ipv4IHL", 208: "ipv4Options", 209: "tcpOptions",
    210: "paddingOctets", 211: "collectorIPv4Address", 212: "collectorIPv6Address", 213: "exportInterface",
    214: "exportProtocolVersion", 215: "exportTransportProtocol", 216: "collectorTransportPort",
    217: "exporterTransportPort", 218: "tcpSynTotalCount", 219: "tcpFinTotalCount", 220: "tcpRstTotalCount",
    221: "tcpPshTotalCount", 222: "tcpAckTotalCount", 223: "tcpUrgTotalCount", 224: "ipTotalLength",
    225: "postNATSourceIPv4Address", 226: "postNATDestinationIPv4Address", 227: "postNAPTSourceTransportPort",
    228: "postNAPTDestinationTransportPort", 229: "natOriginatingAddressRealm", 230: "natEvent",
    231: "initiatorOctets", 232: "responderOctets", 233: "firewallEvent", 234: "ingressVRFID", 235: "egressVRFID",
    236: "VRFname", 237: "postMplsTopLabelExp", 238: "tcpWindowScale", 239: "biflowDirection",
    240: "ethernetHeaderLength", 241: "ethernetPayloadLength", 242: "ethernetTotalLength", 243: "dot1qVlanId",
    244: "dot1qPriority", 245: "dot1qCustomerVlanId", 246: "dot1qCustomerPriority", 247: "metroEvcId",
    248: "metroEvcType", 249: "pseudoWireId", 250: "pseudoWireType", 251: "pseudoWireControlWord",
    252: "ingressPhysicalInterface", 253: "egressPhysicalInterface", 254: "postDot1qVlanId",
    255: "postDot1qCustomerVlanId", 256: "ethernetType", 257: "postIpPrecedence",
    258: "collectionTimeMilliseconds", 259: "exportSctpStreamId", 260: "maxExportSeconds",
    261: "maxFlowEndSeconds", 262: "messageMD5Checksum", 263: "messageScope", 264: "minExportSeconds",
    265: "minFlowStartSeconds", 266: "opaqueOctets", 267: "sessionScope", 268: "maxFlowEndMicroseconds",
    269: "maxFlowEndMilliseconds", 270: "maxFlowEndNanoseconds", 271: "minFlowStartMicroseconds",
    272: "minFlowStartMilliseconds", 273: "minFlowStartNanoseconds", 274: "collectorCertificate",
    275: "exporterCertificate", 276: "dataRecordsReliability", 277: "observationPointType",
    278: "newConnectionDeltaCount", 279: "connectionSumDurationSeconds", 280: "connectionTransactionId",
    281: "postNATSourceIPv6Address", 282: "postNATDestinationIPv6Address", 283: "natPoolId", 284: "natPoolName",
    285: "anonymizationFlags", 286: "anonymizationTechnique", 287: "informationElementIndex", 288: "p2pTechnology",
    289: "tunnelTechnology", 290: "encryptedTechnology", 291: "basicList", 292: "subTemplateList",
    293: "subTemplateMultiList", 294: "bgpValidityState", 295: "IPSecSPI", 296: "greKey", 297: "natType",
    298: "initiatorPackets", 299: "responderPackets", 300: "observationDomainName", 301: "selectionSequenceId",
    302: "selectorId", 303: "informationElementId", 304: "selectorAlgorithm", 305: "samplingPacketInterval",
    306: "samplingPacketSpace", 307: "samplingTimeInterval", 308: "samplingTimeSpace", 309: "samplingSize",
    310: "samplingPopulation", 311: "samplingProbability", 312: "dataLinkFrameSize", 313: "ipHeaderPacketSection",
    314: "ipPayloadPacketSection", 315: "dataLinkFrameSection", 316: "mplsLabelStackSection",
    317: "mplsPayloadPacketSection", 318: "selectorIdTotalPktsObserved", 319: "selectorIdTotalPktsSelected",
    320: "absoluteError", 321: "relativeError", 322: "observationTimeSeconds", 323: "observationTimeMilliseconds",
    324: "observationTimeMicroseconds", 325: "observationTimeNanoseconds", 326: "digestHashValue",
    327: "hashIPPayloadOffset", 328: "hashIPPayloadSize", 329: "hashOutputRangeMin", 330: "hashOutputRangeMax",
    331: "hashSelectedRangeMin", 332: "hashSelectedRangeMax", 333: "hashDigestOutput", 334: "hashInitialiserValue",
    335: "selectorName", 336: "upperCILimit", 337: "lowerCILimit", 338: "confidenceLevel",
    339: "informationElementDataType", 340: "informationElementDescription", 341: "informationElementName",
    342: "informationElementRangeBegin", 343: "informationElementRangeEnd", 344: "informationElementSemantics",
    345: "informationElementUnits", 346: "privateEnterpriseNumber", 347: "virtualStationInterfaceId",
    348: "virtualStationInterfaceName", 349: "virtualStationUUID", 350: "virtualStationName",
    351: "layer2SegmentId", 352: "layer2OctetDeltaCount", 353: "layer2OctetTotalCount",
    354: "ingressUnicastPacketTotalCount", 355: "ingressMulticastPacketTotalCount",
    356: "ingressBroadcastPacketTotalCount", 357: "egressUnicastPacketTotalCount",
    358: "egressBroadcastPacketTotalCount", 359: "monitoringIntervalStartMilliSeconds",
    360: "monitoringIntervalEndMilliSeconds", 361: "portRangeStart", 362: "portRangeEnd", 363: "portRangeStepSize",
    364: "portRangeNumPorts", 365: "staMacAddress", 366: "staIPv4Address", 367: "wtpMacAddress",
    368: "ingressInterfaceType", 369: "egressInterfaceType", 370: "rtpSequenceNumber", 371: "userName",
    372: "applicationCategoryName", 373: "applicationSubCategoryName", 374: "applicationGroupName",
    375: "originalFlowsPresent", 376: "originalFlowsInitiated", 377: "originalFlowsCompleted",
    378: "distinctCountOfSourceIPAddress", 379: "distinctCountOfDestinationIPAddress",
    380: "distinctCountOfSourceIPv4Address", 381: "distinctCountOfDestinationIPv4Address",
    382: "distinctCountOfSourceIPv6Address", 383: "distinctCountOfDestinationIPv6Address",
    384: "valueDistributionMethod", 385: "rfc3550JitterMilliseconds", 386: "rfc3550JitterMicroseconds",
    387: "rfc3550JitterNanoseconds", 388: "dot1qDEI", 389: "dot1qCustomerDEI", 390: "flowSelectorAlgorithm",
    391: "flowSelectedOctetDeltaCount", 392: "flowSelectedPacketDeltaCount", 393: "flowSelectedFlowDeltaCount",
    394: "selectorIDTotalFlowsObserved", 395: "selectorIDTotalFlowsSelected", 396: "samplingFlowInterval",
    397: "samplingFlowSpacing", 398: "flowSamplingTimeInterval", 399: "flowSamplingTimeSpacing",
    400: "hashFlowDomain", 401: "transportOctetDeltaCount", 402: "transportPacketDeltaCount",
    403: "originalExporterIPv4Address", 404: "originalExporterIPv6Address", 405: "originalObservationDomainId",
    406: "intermediateProcessId", 407: "ignoredDataRecordTotalCount", 408: "dataLinkFrameType",
    409: "sectionOffset", 410: "sectionExportedOctets", 411: "dot1qServiceInstanceTag",
    412: "dot1qServiceInstanceId", 413: "dot1qServiceInstancePriority", 414: "dot1qCustomerSourceMacAddress",
    415: "dot1qCustomerDestinationMacAddress", 416: "", 417: "postLayer2OctetDeltaCount",
    418: "postMCastLayer2OctetDeltaCount", 419: "", 420: "postLayer2OctetTotalCount",
    421: "postMCastLayer2OctetTotalCount", 422: "minimumLayer2TotalLength", 423: "maximumLayer2TotalLength",
    424: "droppedLayer2OctetDeltaCount", 425: "droppedLayer2OctetTotalCount", 426: "ignoredLayer2OctetTotalCount",
    427: "notSentLayer2OctetTotalCount", 428: "layer2OctetDeltaSumOfSquares", 429: "layer2OctetTotalSumOfSquares",
    430: "layer2FrameDeltaCount", 431: "layer2FrameTotalCount", 432: "pseudoWireDestinationIPv4Address",
    433: "ignoredLayer2FrameTotalCount", 434: "mibObjectValueInteger", 435: "mibObjectValueOctetString",
    436: "mibObjectValueOID", 437: "mibObjectValueBits", 438: "mibObjectValueIPAddress",
    439: "mibObjectValueCounter", 440: "mibObjectValueGauge", 441: "mibObjectValueTimeTicks",
    442: "mibObjectValueUnsigned", 443: "mibObjectValueTable", 444: "mibObjectValueRow",
    445: "mibObjectIdentifier", 446: "mibSubIdentifier", 447: "mibIndexIndicator", 448: "mibCaptureTimeSemantics",
    449: "mibContextEngineID", 450: "mibContextName", 451: "mibObjectName", 452: "mibObjectDescription",
    453: "mibObjectSyntax", 454: "mibModuleName", 455: "mobileIMSI", 456: "mobileMSISDN", 457: "httpStatusCode",
    458: "sourceTransportPortsLimit", 459: "httpRequestMethod", 460: "httpRequestHost", 461: "httpRequestTarget",
    462: "httpMessageVersion", 463: "natInstanceID", 464: "internalAddressRealm", 465: "externalAddressRealm",
    466: "natQuotaExceededEvent", 467: "natThresholdEvent", 468: "httpUserAgent", 469: "httpContentType",
    470: "httpReasonPhrase", 471: "maxSessionEntries", 472: "maxBIBEntries", 473: "maxEntriesPerUser",
    474: "maxSubscribers", 475: "maxFragmentsPendingReassembly", 476: "addressPoolHighThreshold",
    477: "addressPoolLowThreshold", 478: "addressPortMappingHighThreshold", 479: "addressPortMappingLowThreshold",
    480: "addressPortMappingPerUserHighThreshold", 481: "globalAddressMappingHighThreshold", 482: "vpnIdentifier",
    483: "bgpCommunity", 484: "bgpSourceCommunityList", 485: "bgpDestinationCommunityList",
    486: "bgpExtendedCommunity", 487: "bgpSourceExtendedCommunityList", 488: "bgpDestinationExtendedCommunityList",
    489: "bgpLargeCommunity", 490: "bgpSourceLargeCommunityList", 491: "bgpDestinationLargeCommunityList"
}


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

        # TODO: if padding is needed, implement here

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

        # TODO: if padding is needed, implement here

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

    def __init__(self, data, template):
        self.fields = []
        offset = 0
        unpacker = "!"

        # Iterate through all fields of this template and build the unpack format string
        # TODO: this does not handle signed/unsigned or other types
        # See https://www.iana.org/assignments/ipfix/ipfix.xhtml
        for field_type, field_length in template:
            if field_length == 1:
                unpacker += "B"
            elif field_length == 2:
                unpacker += "H"
            elif field_length == 4:
                unpacker += "I"
            elif field_length == 8:
                unpacker += "Q"
            else:
                # TODO: IPv6 fields have 16 bytes, but struct does not support 16 bytes
                raise IPFIXTemplateError("Template field_length {} not handled in unpacker".format(field_length))
            offset += field_length

        pack = struct.unpack(unpacker, data[0:offset])

        # Iterate through template again, but taking the unpacked value this time
        for (field_type, _), value in zip(template, pack):
            self.fields.append((field_type, value))

        self._length = offset

    def get_length(self):
        return self._length

    @property
    def data(self):
        return {
            IPFIX_FIELD_TYPES.get(key, key): value for (key, value) in self.fields
        }

    def __repr__(self):
        return "<IPFIXDataRecord with {} entries>".format(len(self.fields))


class IPFIXSet:
    """A set containing the set header and a collection of records (one of templates, options, data)
    """

    def __init__(self, data, templates):
        self.header = IPFIXSetHeader(data[0:IPFIXSetHeader.size])
        self.records = []

        offset = IPFIXSetHeader.size
        if self.header.set_id == 2:  # template set
            while offset < self.header.length:  # length of whole set
                template_record = IPFIXTemplateRecord(data[offset:])
                self.records.append(template_record)
                templates[template_record.template_id] = template_record.fields
                offset += template_record.get_length()

        elif self.header.set_id == 3:  # options template
            while offset < self.header.length:
                optionstemplate_record = IPFIXOptionsTemplateRecord(data[offset:])
                self.records.append(optionstemplate_record)
                templates[optionstemplate_record.template_id] = optionstemplate_record.scope_fields + \
                                                                optionstemplate_record.fields
                offset += optionstemplate_record.get_length()

        elif self.header.set_id >= 256:  # data set, set_id is template id
            while offset < self.header.length:
                template = templates.get(self.header.set_id)
                if not template:
                    raise IPFIXTemplateNotRecognized
                data_record = IPFIXDataRecord(data[offset:], template)
                self.records.append(data_record)
                offset += data_record.get_length()
        self._length = offset

    def get_length(self):
        return self._length

    @property
    def is_template(self):
        return self.header.set_id in [2, 3]

    @property
    def is_data(self):
        return self.header.set_id >= 256

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

    def __init__(self, data, templates):
        self.header = IPFIXHeader(data[:IPFIXHeader.size])
        self.sets = []
        self._contains_new_templates = False
        self._flows = []

        offset = IPFIXHeader.size
        while offset < self.header.length:
            new_set = IPFIXSet(data[offset:], templates)
            if new_set.is_template:
                self._contains_new_templates = True
            elif new_set.is_data:
                self._flows += new_set.records

            self.sets.append(new_set)
            offset += new_set.get_length()

        # Here all data should be processed and offset set to the length
        if offset != self.header.length:
            raise IPFIXMalformedPacket

    @property
    def contains_new_templates(self):
        return self._contains_new_templates

    @property
    def flows(self):
        return self._flows

    def __repr__(self):
        return "<IPFIXExportPacket with {} sets, exported at {}>".format(
            len(self.sets), self.header.export_uptime
        )


def parse_fields(data, count: int) -> (list, int):
    offset = 0
    fields = []
    for ctr in range(count):
        if data[offset] & 1 << 7 != 0:  # enterprise flag set
            pack = struct.unpack("!HHI", data[offset:offset + 8])
            fields.append((
                pack[0] & ~(1 << 7),  # ID, clear enterprise flag bit
                pack[1],  # field length
                pack[2]  # enterprise number
            ))
            offset += 8
        else:
            pack = struct.unpack("!HH", data[offset:offset + 4])
            fields.append((
                pack[0],
                pack[1]
            ))
            offset += 4
    return fields, offset
