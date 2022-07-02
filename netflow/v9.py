#!/usr/bin/env python3

"""
Netflow V9 collector and parser implementation in Python 3.
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.
Created for learning purposes and unsatisfying alternatives.

Reference: https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
This script is specifically implemented in combination with softflowd. See https://github.com/djmdjm/softflowd

Copyright 2016-2020 Dominik Pataky <software+pynetflow@dpataky.eu>
Licensed under MIT License. See LICENSE.
"""

import ipaddress
import struct
import sys

from .ipfix import IPFIXFieldTypes, IPFIXDataTypes

__all__ = ["V9DataFlowSet", "V9DataRecord", "V9ExportPacket", "V9Header", "V9TemplateField",
           "V9TemplateFlowSet", "V9TemplateNotRecognized", "V9TemplateRecord",
           "V9OptionsTemplateFlowSet", "V9OptionsTemplateRecord", "V9OptionsDataRecord"]

V9_FIELD_TYPES_CONTAINING_IP = [8, 12, 15, 18, 27, 28, 62, 63]

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
    98: 'postipDiffServCodePoint',  # The value of a Differentiated Services Code Point (DSCP)
                                    # encoded in the Differentiated Services Field, after modification
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
    33001: 'NF_F_EGRESS_ACL_ID',  # The output ACL that permitted or denied a flow
    40000: 'NF_F_USERNAME',  # AAA username

    # PaloAlto PAN-OS 8.0
    # https://www.paloaltonetworks.com/documentation/80/pan-os/pan-os/monitoring/netflow-monitoring/netflow-templates
    346: 'PANOS_privateEnterpriseNumber',
    56701: 'PANOS_APPID',
    56702: 'PANOS_USERID'
}

V9_SCOPE_TYPES = {
    1: "System",
    2: "Interface",
    3: "Line Card",
    4: "Cache",
    5: "Template"
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

    def __init__(self, data, template):
        pack = struct.unpack('!HH', data[:4])

        self.template_id = pack[0]  # flowset_id is reference to a template_id
        self.length = pack[1]
        self.flows = []

        offset = 4

        # As the field lengths are variable V9 has padding to next 32 Bit
        padding_size = 4 - (self.length % 4)  # 4 Byte

        # For performance reasons, we use struct.unpack to get individual values. Here
        # we prepare the format string for parsing it. The format string is based on the template fields and their
        # lengths. The string can then be re-used for every data record in the data stream
        struct_format = '!'
        struct_len = 0
        for field in template.fields:
            # The length of the value byte slice is defined in the template
            flen = field.field_length
            if flen == 4:
                struct_format += 'L'
            elif flen == 2:
                struct_format += 'H'
            elif flen == 1:
                struct_format += 'B'
            else:
                struct_format += '%ds' % flen
            struct_len += flen

        while offset <= (self.length - padding_size):
            # Here we actually unpack the values, the struct format string is used in every data record
            # iteration, until the final offset reaches the end of the whole data stream
            unpacked_values = struct.unpack(struct_format, data[offset:offset + struct_len])

            new_record = V9DataRecord()
            for field, value in zip(template.fields, unpacked_values):
                flen = field.field_length
                fkey = V9_FIELD_TYPES[field.field_type]

                # Special handling of IP addresses to convert integers to strings to not lose precision in dump
                # TODO: might only be needed for IPv6
                if field.field_type in V9_FIELD_TYPES_CONTAINING_IP:
                    try:
                        ip = ipaddress.ip_address(value)
                    except ValueError:
                        print("IP address could not be parsed: {}".format(repr(value)))
                        continue
                    new_record.data[fkey] = ip.compressed
                elif flen in (1, 2, 4):
                    # These values are already converted to numbers by struct.unpack:
                    new_record.data[fkey] = value
                else:
                    # Caveat: this code assumes little-endian system (like x86)
                    if sys.byteorder != "little":
                        print("v9.py uses bit shifting for little endianness. Your processor is not little endian")

                    fdata = 0
                    for idx, byte in enumerate(reversed(bytearray(value))):
                        fdata += byte << (idx * 8)
                    new_record.data[fkey] = fdata

                offset += flen

            new_record.__dict__.update(new_record.data)
            self.flows.append(new_record)

    def __repr__(self):
        return "<DataFlowSet with template {} of length {} holding {} flows>" \
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

    def __init__(self, template_id, field_count, fields: list):
        self.template_id = template_id
        self.field_count = field_count
        self.fields = fields

    def __repr__(self):
        return "<TemplateRecord {} with {} fields: {}>".format(
            self.template_id, self.field_count,
            ' '.join([V9_FIELD_TYPES[field.field_type] for field in self.fields]))


class V9OptionsDataRecord:
    def __init__(self):
        self.scopes = {}
        self.data = {}

    def __repr__(self):
        return "<V9OptionsDataRecord with scopes {} and data {}>".format(self.scopes.keys(), self.data.keys())


class V9OptionsTemplateRecord:
    """An options template record contained in an options template flowset.
    """

    def __init__(self, template_id, scope_fields: dict, option_fields: dict):
        self.template_id = template_id
        self.scope_fields = scope_fields
        self.option_fields = option_fields

    def __repr__(self):
        return "<V9OptionsTemplateRecord with scope fields {} and option fields {}>".format(
            self.scope_fields.keys(), self.option_fields.keys())


class V9OptionsTemplateFlowSet:
    """An options template flowset.

    > Each Options Template FlowSet MAY contain multiple Options Template Records.

    Scope field types range from 1 to 5:
        1 System
        2 Interface
        3 Line Card
        4 Cache
        5 Template
    """

    def __init__(self, data: bytes):
        pack = struct.unpack('!HH', data[:4])
        self.flowset_id = pack[0]  # always 1
        self.flowset_length = pack[1]  # length of this flowset
        self.templates = {}

        offset = 4

        while offset < self.flowset_length:
            pack = struct.unpack("!HHH", data[offset:offset + 6])  # options template header
            template_id = pack[0]  # value above 255
            option_scope_length = pack[1]
            options_length = pack[2]

            offset += 6

            # Fetch all scope fields (most probably only one field)
            scopes = {}  # Holds "type: length" key-value pairs

            if option_scope_length % 4 != 0 or options_length % 4 != 0:
                raise ValueError(option_scope_length, options_length)

            for scope_counter in range(option_scope_length // 4):  # example: option_scope_length = 4 means one scope
                pack = struct.unpack("!HH", data[offset:offset + 4])
                scope_field_type = pack[0]  # values range from 1 to 5
                scope_field_length = pack[1]
                scopes[scope_field_type] = scope_field_length
                offset += 4

            # Fetch all option fields
            options = {}  # same
            for option_counter in range(options_length // 4):  # now counting the options
                pack = struct.unpack("!HH", data[offset:offset + 4])
                option_field_type = pack[0]
                option_field_length = pack[1]
                options[option_field_type] = option_field_length
                offset += 4

            optionstemplate = V9OptionsTemplateRecord(template_id, scopes, options)

            self.templates[template_id] = optionstemplate

            # handle padding and add offset if needed
            if offset % 4 == 2:
                offset += 2

    def __repr__(self):
        return "<V9OptionsTemplateFlowSet with {} templates: {}>".format(len(self.templates), self.templates.keys())


class V9OptionsDataFlowset:
    """An options data flowset with option data records
    """

    def __init__(self, data: bytes, template: V9OptionsTemplateRecord):
        pack = struct.unpack('!HH', data[:4])

        self.template_id = pack[0]
        self.length = pack[1]
        self.option_data_records = []

        offset = 4

        while offset < self.length:
            new_options_record = V9OptionsDataRecord()

            for scope_type, length in template.scope_fields.items():
                type_name = V9_SCOPE_TYPES.get(scope_type, scope_type)  # Either name, or unknown int
                value = int.from_bytes(data[offset:offset + length], 'big')  # TODO: is this always integer?
                new_options_record.scopes[type_name] = value
                offset += length

            for field_type, length in template.option_fields.items():
                type_name = V9_FIELD_TYPES.get(field_type, None)
                is_bytes = False

                if not type_name:  # Cisco refers to the IANA IPFIX table for types >256...
                    iana_type = IPFIXFieldTypes.by_id(field_type)  # try to get from IPFIX types
                    if iana_type:
                        type_name = iana_type.name
                        is_bytes = IPFIXDataTypes.is_bytes(iana_type)

                if not type_name:
                    raise ValueError

                value = None
                if is_bytes:
                    value = data[offset:offset + length]
                else:
                    value = int.from_bytes(data[offset:offset + length], 'big')

                new_options_record.data[type_name] = value

                offset += length

            self.option_data_records.append(new_options_record)

            if offset % 4 == 2:
                offset += 2


class V9TemplateFlowSet:
    """A template flowset, which holds an id that is used by data flowsets to
    reference back to the template. The template then has fields which hold
    identifiers of data types (eg "IP_SRC_ADDR", "PKTS"..). This way the flow
    sender can dynamically put together data flowsets.
    """

    def __init__(self, data):
        pack = struct.unpack('!HH', data[:4])
        self.flowset_id = pack[0]  # always 0
        self.length = pack[1]  # total length including this header in bytes
        self.templates = {}

        offset = 4  # Skip header

        # Iterate through all template records in this template flowset
        while offset < self.length:
            pack = struct.unpack('!HH', data[offset:offset + 4])
            template_id = pack[0]
            field_count = pack[1]

            fields = []
            for field in range(field_count):
                # Get all fields of this template
                offset += 4
                field_type, field_length = struct.unpack('!HH', data[offset:offset + 4])
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
        return "<TemplateFlowSet with id {} of length {} containing templates: {}>" \
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

    TODO: refactor into two loops: first get all contained flowsets and examine template
        flowsets first. Then data flowsets.
    """

    def __init__(self, data: bytes, templates: dict):
        self.header = V9Header(data)
        self._templates = templates
        self._new_templates = False
        self._flows = []
        self._options = []

        offset = self.header.length
        skipped_flowsets_offsets = []

        while offset != len(data):
            pack = struct.unpack('!HH', data[offset:offset + 4])
            flowset_id = pack[0]  # = template id
            flowset_length = pack[1]

            # Data template flowsets
            if flowset_id == 0:  # TemplateFlowSet always have id 0
                tfs = V9TemplateFlowSet(data[offset:])
                # Update the templates with the provided templates, even if they are the same
                for id_, template in tfs.templates.items():
                    if id_ not in self._templates:
                        self._new_templates = True
                    self._templates[id_] = template
                if tfs.length == 0:
                    break
                offset += tfs.length
                continue

            # Option template flowsets
            elif flowset_id == 1:  # Option templates always use ID 1
                otfs = V9OptionsTemplateFlowSet(data[offset:])
                for id_, template in otfs.templates.items():
                    if id_ not in self._templates:
                        self._new_templates = True
                    self._templates[id_] = template
                offset += otfs.flowset_length
                if otfs.flowset_length == 0:
                    break
                continue

            # Data / option flowsets
            # First, check if template is known
            if flowset_id not in self._templates:
                # Could not be parsed, continue to check for templates
                skipped_flowsets_offsets.append(offset)
                offset += flowset_length
                if flowset_length == 0:
                    break
                continue

            matched_template = self._templates[flowset_id]

            if isinstance(matched_template, V9TemplateRecord):
                dfs = V9DataFlowSet(data[offset:], matched_template)
                self._flows += dfs.flows
                if dfs.length == 0:
                    break
                offset += dfs.length

            elif isinstance(matched_template, V9OptionsTemplateRecord):
                odfs = V9OptionsDataFlowset(data[offset:], matched_template)
                self._options += odfs.option_data_records
                if odfs.length == 0:
                    break
                offset += odfs.length

            else:
                raise NotImplementedError

        # In the same export packet, re-try flowsets with previously unknown templates.
        # Might happen, if an export packet first contains data flowsets, and template flowsets after
        if skipped_flowsets_offsets and self._new_templates:
            # Process flowsets in the data slice which occured before the template sets
            # Handling of offset increases is not needed here
            for offset in skipped_flowsets_offsets:
                pack = struct.unpack('!H', data[offset:offset + 2])
                flowset_id = pack[0]

                if flowset_id not in self._templates:
                    raise V9TemplateNotRecognized

                matched_template = self._templates[flowset_id]
                if isinstance(matched_template, V9TemplateRecord):
                    dfs = V9DataFlowSet(data[offset:], matched_template)
                    self._flows += dfs.flows
                elif isinstance(matched_template, V9OptionsTemplateRecord):
                    odfs = V9OptionsDataFlowset(data[offset:], matched_template)
                    self._options += odfs.option_data_records

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

    @property
    def options(self):
        return self._options

    def __repr__(self):
        s = " and new template(s)" if self.contains_new_templates else ""
        return "<V9ExportPacket with {} records{}>".format(self.header.count, s)
