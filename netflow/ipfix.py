#!/usr/bin/env python3

"""
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.
Reference: https://tools.ietf.org/html/rfc7011

Copyright 2016-2020 Dominik Pataky <dev@bitkeks.eu>
Licensed under MIT License. See LICENSE.
"""

import struct


class IPFIXMalformedRecord(Exception):
    pass


class IPFIXRFCError(Exception):
    pass


class IPFIXMalformedPacket(Exception):
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

        # if offset % 4 != 0:  # padding included in record, must be zero
        #     to_fill = (4 - offset % 4)
        #     if data[offset:offset + to_fill] != 0:
        #         raise IPFIXMalformedRecord
        #     offset += to_fill
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

        # if offset % 4 != 0:  # padding included in record, must be zero
        #     to_fill = (4 - offset % 4)
        #     if data[offset:offset + to_fill] != 0:
        #         raise IPFIXMalformedRecord
        #     offset += to_fill
        self._length = offset

    def get_length(self):
        return self._length

    def __repr__(self):
        return "<IPFIXOptionsTemplateRecord with {} scope fields and {} fields>".format(
            len(self.scope_fields), len(self.fields)
        )


class IPFIXDataRecord:
    def __init__(self, data, template_id):
        pass


class IPFIXSet:
    """A set containing the set header and a collection of records (templates, options, data)
    """
    def __init__(self, data, templates):
        self.header = IPFIXSetHeader(data[0:IPFIXSetHeader.size])
        self.records = []

        offset = IPFIXSetHeader.size
        if self.header.set_id == 2:  # template set
            while offset < self.header.length:  # length of whole set
                template_record = IPFIXTemplateRecord(data[offset:])
                self.records.append(template_record)
                offset += template_record.get_length()
        elif self.header.set_id == 3:  # options template
            while offset < self.header.length:
                optionstemplate_record = IPFIXOptionsTemplateRecord(data[offset:])
                self.records.append(optionstemplate_record)
                offset += optionstemplate_record.get_length()
        elif self.header.set_id >= 256:  # data set
            pass
            # while offset < self.header.length:
            #     data_record = IPFIXDataRecord(data[offset:], None)
            #     self.records.append(data_record)
            #     offset += 0
        self._length = offset

    def get_length(self):
        return self._length

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

        offset = IPFIXHeader.size
        while offset < self.header.length:
            new_set = IPFIXSet(data[offset:], templates)
            self.sets.append(new_set)
            offset += new_set.get_length()

        # Here all data should be processed and offset set to the length
        if offset != self.header.length:
            raise IPFIXMalformedPacket

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
