#!/usr/bin/env python3

"""
Netflow V9 collector and parser implementation in Python 3.
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.
Created for learning purposes and unsatisfying alternatives.

Reference: https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
This script is specifically implemented in combination with softflowd. See https://github.com/djmdjm/softflowd

Copyright 2016-2020 Dominik Pataky <dev@bitkeks.eu>
Licensed under MIT License. See LICENSE.
"""

import ipaddress
import struct

__all__ = ["V9DataFlowSet", "V9DataRecord", "V9ExportPacket", "V9Header", "V9TemplateField",
           "V9TemplateFlowSet", "V9TemplateNotRecognized", "V9TemplateRecord"]

V9_FIELD_TYPES = {
    0: 'UNKNOWN_FIELD_TYPE',  # fallback for unknown field types

    # Cisco specs for NetFlow v9
    # https://tools.ietf.org/html/rfc3954
    # https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
    1: 'IN_BYTES',
    2: 'IN_PKTS',
    3: 'FLOWS',
    4: 'PROTOCOL',
    5: 'SRC_TOS',
    6: 'TCP_FLAGS',
    7: 'L4_SRC_PORT',
    8: 'IPV4_SRC_ADDR',
    9: 'SRC_MASK',
    10: 'INPUT_SNMP',
    11: 'L4_DST_PORT',
    12: 'IPV4_DST_ADDR',
    13: 'DST_MASK',
    14: 'OUTPUT_SNMP',
    15: 'IPV4_NEXT_HOP',
    16: 'SRC_AS',
    17: 'DST_AS',
    18: 'BGP_IPV4_NEXT_HOP',
    19: 'MUL_DST_PKTS',
    20: 'MUL_DST_BYTES',
    21: 'LAST_SWITCHED',
    22: 'FIRST_SWITCHED',
    23: 'OUT_BYTES',
    24: 'OUT_PKTS',
    25: 'MIN_PKT_LNGTH',
    26: 'MAX_PKT_LNGTH',
    27: 'IPV6_SRC_ADDR',
    28: 'IPV6_DST_ADDR',
    29: 'IPV6_SRC_MASK',
    30: 'IPV6_DST_MASK',
    31: 'IPV6_FLOW_LABEL',
    32: 'ICMP_TYPE',
    33: 'MUL_IGMP_TYPE',
    34: 'SAMPLING_INTERVAL',
    35: 'SAMPLING_ALGORITHM',
    36: 'FLOW_ACTIVE_TIMEOUT',
    37: 'FLOW_INACTIVE_TIMEOUT',
    38: 'ENGINE_TYPE',
    39: 'ENGINE_ID',
    40: 'TOTAL_BYTES_EXP',
    41: 'TOTAL_PKTS_EXP',
    42: 'TOTAL_FLOWS_EXP',
    # 43 vendor proprietary
    44: 'IPV4_SRC_PREFIX',
    45: 'IPV4_DST_PREFIX',
    46: 'MPLS_TOP_LABEL_TYPE',
    47: 'MPLS_TOP_LABEL_IP_ADDR',
    48: 'FLOW_SAMPLER_ID',
    49: 'FLOW_SAMPLER_MODE',
    50: 'NTERVAL',
    # 51 vendor proprietary
    52: 'MIN_TTL',
    53: 'MAX_TTL',
    54: 'IPV4_IDENT',
    55: 'DST_TOS',
    56: 'IN_SRC_MAC',
    57: 'OUT_DST_MAC',
    58: 'SRC_VLAN',
    59: 'DST_VLAN',
    60: 'IP_PROTOCOL_VERSION',
    61: 'DIRECTION',
    62: 'IPV6_NEXT_HOP',
    63: 'BPG_IPV6_NEXT_HOP',
    64: 'IPV6_OPTION_HEADERS',
    # 65-69 vendor proprietary
    70: 'MPLS_LABEL_1',
    71: 'MPLS_LABEL_2',
    72: 'MPLS_LABEL_3',
    73: 'MPLS_LABEL_4',
    74: 'MPLS_LABEL_5',
    75: 'MPLS_LABEL_6',
    76: 'MPLS_LABEL_7',
    77: 'MPLS_LABEL_8',
    78: 'MPLS_LABEL_9',
    79: 'MPLS_LABEL_10',
    80: 'IN_DST_MAC',
    81: 'OUT_SRC_MAC',
    82: 'IF_NAME',
    83: 'IF_DESC',
    84: 'SAMPLER_NAME',
    85: 'IN_PERMANENT_BYTES',
    86: 'IN_PERMANENT_PKTS',
    # 87 vendor property
    88: 'FRAGMENT_OFFSET',
    89: 'FORWARDING_STATUS',
    90: 'MPLS_PAL_RD',
    91: 'MPLS_PREFIX_LEN',  # Number of consecutive bits in the MPLS prefix length.
    92: 'SRC_TRAFFIC_INDEX',  # BGP Policy Accounting Source Traffic Index
    93: 'DST_TRAFFIC_INDEX',  # BGP Policy Accounting Destination Traffic Index
    94: 'APPLICATION_DESCRIPTION',  # Application description
    95: 'APPLICATION_TAG',  # 8 bits of engine ID, followed by n bits of classification
    96: 'APPLICATION_NAME',  # Name associated with a classification
    98: 'postipDiffServCodePoint',  # The value of a Differentiated Services Code Point (DSCP) encoded in the Differentiated Services Field, after modification
    99: 'replication_factor',  # Multicast replication factor
    100: 'DEPRECATED',  # DEPRECATED
    102: 'layer2packetSectionOffset',  # Layer 2 packet section offset. Potentially a generic offset
    103: 'layer2packetSectionSize',  # Layer 2 packet section size. Potentially a generic size
    104: 'layer2packetSectionData',  # Layer 2 packet section data
    # 105-127 reserved for future use by Cisco

    # ASA extensions
    # https://www.cisco.com/c/en/us/td/docs/security/asa/special/netflow/guide/asa_netflow.html
    148: 'NF_F_CONN_ID',  # An identifier of a unique flow for the device
    176: 'NF_F_ICMP_TYPE',  # ICMP type value
    177: 'NF_F_ICMP_CODE',  # ICMP code value
    178: 'NF_F_ICMP_TYPE_IPV6',  # ICMP IPv6 type value
    179: 'NF_F_ICMP_CODE_IPV6',  # ICMP IPv6 code value
    225: 'NF_F_XLATE_SRC_ADDR_IPV4',  # Post NAT Source IPv4 Address
    226: 'NF_F_XLATE_DST_ADDR_IPV4',  # Post NAT Destination IPv4 Address
    227: 'NF_F_XLATE_SRC_PORT',  # Post NATT Source Transport Port
    228: 'NF_F_XLATE_DST_PORT',  # Post NATT Destination Transport Port
    281: 'NF_F_XLATE_SRC_ADDR_IPV6',  # Post NAT Source IPv6 Address
    282: 'NF_F_XLATE_DST_ADDR_IPV6',  # Post NAT Destination IPv6 Address
    233: 'NF_F_FW_EVENT',  # High-level event code
    33002: 'NF_F_FW_EXT_EVENT',  # Extended event code
    323: 'NF_F_EVENT_TIME_MSEC',  # The time that the event occurred, which comes from IPFIX
    152: 'NF_F_FLOW_CREATE_TIME_MSEC',
    231: 'NF_F_FWD_FLOW_DELTA_BYTES',  # The delta number of bytes from source to destination
    232: 'NF_F_REV_FLOW_DELTA_BYTES',  # The delta number of bytes from destination to source
    33000: 'NF_F_INGRESS_ACL_ID',  # The input ACL that permitted or denied the flow
    33001: 'NF_F_EGRESS_ACL_ID',  #  The output ACL that permitted or denied a flow
    40000: 'NF_F_USERNAME',  # AAA username

    # PaloAlto PAN-OS 8.0
    # https://www.paloaltonetworks.com/documentation/80/pan-os/pan-os/monitoring/netflow-monitoring/netflow-templates
    346: 'PANOS_privateEnterpriseNumber',
    56701: 'PANOS_APPID',
    56702: 'PANOS_USERID'
}


class V9TemplateNotRecognized(KeyError):
    pass


class V9DataRecord:
    """This is a 'flow' as we want it from our source. What it contains is
    variable in NetFlow V9, so to work with the data you have to analyze the
    data dict keys (which are integers and can be mapped with the FIELD_TYPES
    dict).
    Should hold a 'data' dict with keys=field_type (integer) and value (in bytes).
    """
    def __init__(self):
        self.data = {}

    def __repr__(self):
        return "<DataRecord with data: {}>".format(self.data)


class V9DataFlowSet:
    """Holds one or multiple DataRecord which are all defined after the same
    template. This template is referenced in the field 'flowset_id' of this
    DataFlowSet and must not be zero.
    """
    def __init__(self, data, templates):
        pack = struct.unpack('!HH', data[:4])

        self.template_id = pack[0]  # flowset_id is reference to a template_id
        self.length = pack[1]
        self.flows = []

        offset = 4

        if self.template_id not in templates:
            raise V9TemplateNotRecognized

        template = templates[self.template_id]

        # As the field lengths are variable V9 has padding to next 32 Bit
        padding_size = 4 - (self.length % 4)  # 4 Byte

        while offset <= (self.length - padding_size):
            new_record = V9DataRecord()

            for field in template.fields:
                flen = field.field_length
                fkey = V9_FIELD_TYPES[field.field_type]

                # The length of the value byte slice is defined in the template
                dataslice = data[offset:offset+flen]

                # Better solution than struct.unpack with variable field length
                fdata = 0
                for idx, byte in enumerate(reversed(bytearray(dataslice))):
                    fdata += byte << (idx * 8)

                # Special handling of IP addresses to convert integers to strings to not lose precision in dump
                # TODO: might only be needed for IPv6
                if fkey in ["IPV4_SRC_ADDR", "IPV4_DST_ADDR", "IPV6_SRC_ADDR", "IPV6_DST_ADDR"]:
                    try:
                        ip = ipaddress.ip_address(fdata)
                    except ValueError:
                        print("IP address could not be parsed: {}".format(fdata))
                        continue
                    new_record.data[fkey] = ip.compressed
                else:
                    new_record.data[fkey] = fdata

                offset += flen

            new_record.__dict__.update(new_record.data)
            self.flows.append(new_record)

    def __repr__(self):
        return "<DataFlowSet with template {} of length {} holding {} flows>"\
            .format(self.template_id, self.length, len(self.flows))


class V9TemplateField:
    """A field with type identifier and length.
    """
    def __init__(self, field_type, field_length):
        self.field_type = field_type  # integer
        self.field_length = field_length  # bytes

    def __repr__(self):
        return "<TemplateField type {}:{}, length {}>".format(
            self.field_type, V9_FIELD_TYPES[self.field_type], self.field_length)


class V9TemplateRecord:
    """A template record contained in a TemplateFlowSet.
    """
    def __init__(self, template_id, field_count, fields):
        self.template_id = template_id
        self.field_count = field_count
        self.fields = fields

    def __repr__(self):
        return "<TemplateRecord {} with {} fields: {}>".format(
            self.template_id, self.field_count,
            ' '.join([V9_FIELD_TYPES[field.field_type] for field in self.fields]))


class V9TemplateFlowSet:
    """A template flowset, which holds an id that is used by data flowsets to
    reference back to the template. The template then has fields which hold
    identifiers of data types (eg "IP_SRC_ADDR", "PKTS"..). This way the flow
    sender can dynamically put together data flowsets.
    """
    def __init__(self, data):
        pack = struct.unpack('!HH', data[:4])
        self.flowset_id = pack[0]
        self.length = pack[1]  # total length including this header in bytes
        self.templates = {}

        offset = 4  # Skip header

        # Iterate through all template records in this template flowset
        while offset < self.length:
            pack = struct.unpack('!HH', data[offset:offset+4])
            template_id = pack[0]
            field_count = pack[1]

            fields = []
            for field in range(field_count):
                # Get all fields of this template
                offset += 4
                field_type, field_length = struct.unpack('!HH', data[offset:offset+4])
                if field_type not in V9_FIELD_TYPES:
                    field_type = 0  # Set field_type to UNKNOWN_FIELD_TYPE as fallback
                field = V9TemplateField(field_type, field_length)
                fields.append(field)

            # Create a template object with all collected data
            template = V9TemplateRecord(template_id, field_count, fields)

            # Append the new template to the global templates list
            self.templates[template.template_id] = template

            # Set offset to next template_id field
            offset += 4

    def __repr__(self):
        return "<TemplateFlowSet with id {} of length {} containing templates: {}>"\
            .format(self.flowset_id, self.length, self.templates.keys())


class V9Header:
    """The header of the V9ExportPacket
    """
    length = 20

    def __init__(self, data):
        pack = struct.unpack('!HHIIII', data[:self.length])
        self.version = pack[0]
        self.count = pack[1]  # not sure if correct. softflowd: no of flows
        self.uptime = pack[2]
        self.timestamp = pack[3]
        self.sequence = pack[4]
        self.source_id = pack[5]

    def to_dict(self):
        return self.__dict__


class V9ExportPacket:
    """The flow record holds the header and all template and data flowsets.
    """
    def __init__(self, data, templates):
        self.header = V9Header(data)
        self._templates = templates
        self._new_templates = False
        self._flows = []

        offset = self.header.length
        skipped_flowsets_offsets = []
        while offset != len(data):
            flowset_id = struct.unpack('!H', data[offset:offset+2])[0]
            if flowset_id == 0:  # TemplateFlowSet always have id 0
                tfs = V9TemplateFlowSet(data[offset:])

                # Check for any new/changed templates
                if not self._new_templates:
                    for id_, template in tfs.templates.items():
                        if id_ not in self._templates or self._templates[id_] != template:
                            self._new_templates = True
                            break

                # Update the templates with the provided templates, even if they are the same
                self._templates.update(tfs.templates)
                offset += tfs.length
            else:
                try:
                    dfs = V9DataFlowSet(data[offset:], self._templates)
                    self._flows += dfs.flows
                    offset += dfs.length
                except V9TemplateNotRecognized:
                    # Could not be parsed, continue to check for templates
                    length = struct.unpack("!H", data[offset+2:offset+4])[0]
                    skipped_flowsets_offsets.append(offset)
                    offset += length

        if skipped_flowsets_offsets and self._new_templates:
            # Process flowsets in the data slice which occured before the template sets
            for offset in skipped_flowsets_offsets:
                dfs = V9DataFlowSet(data[offset:], self._templates)
                self._flows += dfs.flows
        elif skipped_flowsets_offsets:
            raise V9TemplateNotRecognized

    @property
    def contains_new_templates(self):
        return self._new_templates

    @property
    def flows(self):
        return self._flows

    @property
    def templates(self):
        return self._templates

    def __repr__(self):
        s = " and new template(s)" if self.contains_new_templates else ""
        return "<ExportPacket v{} with {} records{}>".format(
            self.header.version, self.header.count, s)
