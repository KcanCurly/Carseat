# This file contains code from Tivan, available at https://github.com/irtimmer/tivan.
# Copyright (C) Iwan Timmer.
#
# This file is part of Carseat.
# Copyright (C) 2024 Steven F
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.


import struct, uuid
from xml.sax.saxutils import escape
from impacket.dcerpc.v5 import even6, transport, epm
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, DCERPCException
from impacket.uuid import uuidtup_to_bin
#from impacket.structure import Structure, hexdump
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


EVEN6_UUID = uuidtup_to_bin(('F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C', '1.0'))
MSRPC_UUID_EPM = uuidtup_to_bin(('E1AF8308-5D1F-11C9-91A4-08002B14A0FA', '3.0'))

#https://github.com/irtimmer/tivan/blob/master/tivan/parser/binxml.py

class Substitution:
    def __init__(self, buf, offset):
        (sub_token, sub_id, sub_type) = struct.unpack_from('<BHB', buf, offset)
        self.length = 4

        self._id = sub_id
        self._type = sub_type
        self._optional = sub_token == 0x0e

    def xml(self, template = None):
        value = template.values[self._id]
        if value.type == 0x0:
            return None if self._optional else ""
        if self._type == 0x1:
            return value.data.decode('utf16')
        elif self._type == 0x4:
            return str(struct.unpack('<B', value.data)[0])
        elif self._type == 0x6:
            return str(struct.unpack('<H', value.data)[0])
        elif self._type == 0x7:
            return str(struct.unpack('<i', value.data)[0])
        elif self._type == 0x8:
            return str(struct.unpack('<I', value.data)[0])
        elif self._type == 0xa:
            return str(struct.unpack('<Q', value.data)[0])
        elif self._type == 0x11:
            timestamp = struct.unpack('<Q', value.data)[0] / 1e7 - 11644473600
            return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
            #return datetime.utcfromtimestamp(struct.unpack('<Q', value.data)[0] / 1e7 - 11644473600).isoformat()
        elif self._type == 0x13:
            revision, number_of_sub_ids = struct.unpack_from('<BB', value.data)
            iav = struct.unpack_from('>Q', value.data, 2)[0]
            sub_ids = [struct.unpack('<I', value.data[8 + 4 * i:12 + 4 * i])[0] for i in range(number_of_sub_ids)]
            return 'S-{0}-{1}-{2}'.format(revision, iav, '-'.join([str(sub_id) for sub_id in sub_ids]))
        elif self._type == 0x15 or self._type == 0x10:
            return value.data.hex()
        elif self._type == 0x21:
            return value.template.xml()
        elif self._type == 0xf:
            return str(uuid.UUID(bytes_le=value.data))
        else:
            print("Unknown value type", hex(value.type))

class Value:
    def __init__(self, buf, offset):
        token, string_type, length = struct.unpack_from('<BBH', buf, offset)
        self._val = buf[offset + 4:offset + 4 + length * 2].decode("utf16")

        self.length = 4 + length * 2

    def xml(self, template = None):
        return self._val

class Attribute:
    def __init__(self, buf, offset):
        token = struct.unpack_from('<B', buf, offset)
        self._name = Name(buf, offset + 1)

        (next_token) = struct.unpack_from('<B', buf, offset + 1 + self._name.length)
        if next_token[0] == 0x05 or next_token == 0x45:
            self._value = Value(buf, offset + 1 + self._name.length)
        elif next_token[0] == 0x0e:
            self._value = Substitution(buf, offset + 1 + self._name.length)
        else:
            print("Unknown attribute next_token", hex(next_token[0]), hex(offset + 1 + self._name.length))

        self.length = 1 + self._name.length + self._value.length

    def xml(self, template = None):
        val = self._value.xml(template)
        return None if val == None else '{}="{}"'.format(self._name.val, val)

class Name:
    def __init__(self, buf, offset):
        hash, length = struct.unpack_from('<HH', buf, offset)

        self.val = buf[offset + 4:offset + 4 + length * 2].decode("utf16")
        self.length = 4 + (length + 1) * 2

class Element:
    def __init__(self, buf, offset):
        token, dependency_id, length = struct.unpack_from('<BHI', buf, offset)

        self._name = Name(buf, offset + 7)
        self._dependency = dependency_id

        ofs = offset + 7 + self._name.length
        if token == 0x41:
            attr_len = struct.unpack_from('<I', buf, ofs)
            ofs += 4

        self._children = []
        self._attributes = []

        while True:
            next_token = buf[ofs]
            if next_token == 0x06 or next_token == 0x46:
                attr = Attribute(buf, ofs)
                self._attributes.append(attr)
                ofs += attr.length
            elif next_token == 0x02:
                self._empty = False
                ofs += 1
                while True:
                    next_token = buf[ofs]
                    if next_token == 0x01 or next_token == 0x41:
                        element = Element(buf, ofs)
                    elif next_token == 0x04:
                        ofs += 1
                        break
                    elif next_token == 0x05:
                        element = Value(buf, ofs)
                    elif next_token == 0x0e or next_token == 0x0d:
                        element = Substitution(buf, ofs)
                    else:
                        print("Unknown intern next_token", hex(next_token), hex(ofs))
                        break

                    self._children.append(element)
                    ofs += element.length

                break
            elif next_token == 0x03:
                self._empty = True
                ofs += 1
                break
            else:
                print("Unknown element next_token", hex(next_token), hex(ofs))
                break

        self.length = ofs - offset

    def xml(self, template = None):
        if self._dependency != 0xFFFF:
            if template.values[self._dependency].type == 0x00:
                return ""

        attrs = filter(lambda x: x != None, map(lambda x: x.xml(template), self._attributes))
        
        attrs = " ".join(attrs)
        if len(attrs) > 0:
            attrs = " " + attrs
            
        if self._empty:
            return "<{}{}/>".format(self._name.val, attrs)
        else:
            children = map(lambda x: x.xml(template), self._children)
            return "<{}{}>{}</{}>".format(self._name.val, attrs, "".join(children), self._name.val)

class ValueSpec:
    def __init__(self, buf, offset, value_offset):
        self.length, self.type, value_eof = struct.unpack_from('<HBB', buf, offset)
        self.data = buf[value_offset:value_offset + self.length]

        if self.type == 0x21:
            self.template = BinXML(buf, value_offset)

class TemplateInstance:
    def __init__(self, buf, offset):
        token, unknown0, guid, length, next_token = struct.unpack_from('<BB16sIB', buf, offset)
        if next_token == 0x0F:
            self._xml = BinXML(buf, offset + 0x16)
            eof, num_values = struct.unpack_from('<BI', buf, offset + 22 + self._xml.length)
            values_length = 0
            self.values = []
            for x in range(0, num_values):
                value = ValueSpec(buf, offset + 22 + self._xml.length + 5 + x * 4, offset + 22 + self._xml.length + 5 + num_values * 4 + values_length)
                self.values.append(value)
                values_length += value.length

            self.length = 22 + self._xml.length + 5 + num_values * 4 + values_length
        else:
            print("Unknown template token", hex(next_token))

    def xml(self, template = None):
        return self._xml.xml(self)

class BinXML:
    def __init__(self, buf, offset):
        header_token, major_version, minor_version, flags, next_token = struct.unpack_from('<BBBBB', buf, offset)

        if next_token == 0x0C:
            self._element = TemplateInstance(buf, offset + 4)
        elif next_token == 0x01 or next_token == 0x41:
            self._element = Element(buf, offset + 4)
        else:
            print("Unknown binxml token", hex(next_token))

        self.length = 4 + self._element.length

    def xml(self, template = None):
        return self._element.xml(template)

class ResultSet:
    def __init__(self, buf):
        total_size, header_size, event_offset, bookmark_offset, binxml_size = struct.unpack_from('<IIIII', buf)
        self._xml = BinXML(buf, 0x14)

    def xml(self):
        return self._xml.xml()


class EVENHandler:
    def __init__(self, target, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = ''
        self.nthash = ''
        self.aesKey = aesKey
        self.doKerberos = doKerberos
        self.kdcHost = kdcHost
        if hashes is not None:
            self.lmhash, self.nthash = hashes.split(':')
        self.dce = None

    def connect(self):
        binding = epm.hept_map(destHost=self.target, remoteIf=EVEN6_UUID, protocol = 'ncacn_ip_tcp')
        try:
            rpctransport = transport.DCERPCTransportFactory(binding)

            if hasattr(rpctransport, 'set_credentials'):
                rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey)
            if self.doKerberos:
                rpctransport.set_kerberos(self.doKerberos, kdcHost=self.target)
            if self.kdcHost is not None:
                rpctransport.setRemoteHost(self.kdcHost)
                rpctransport.setRemoteName(self.target)

            self.dce = rpctransport.get_dce_rpc()
            self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
            self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            self.dce.connect()
            self.dce.bind(EVEN6_UUID)
            return self.dce, rpctransport

        except Exception as e:
            print(f"Error during connection: {str(e)}")
            raise

    def EvtRpcRegisterLogQuery_EvtRpcQueryNext(self, log_name, query):
        batch_size = 200
        request = even6.EvtRpcRegisterLogQuery()
        request['Path'] = f'{log_name}\x00'
        request['Query'] = f'{query}\x00'
        request['Flags'] = even6.EvtQueryChannelName | even6.EvtReadNewestToOldest
        resp = self.dce.request(request)
        log_handle = resp['Handle']
        
        while True:
            request = even6.EvtRpcQueryNext()
            request['LogQuery'] = log_handle
            request['NumRequestedRecords'] = batch_size
            request['TimeOutEnd'] = 1000
            request['Flags'] = 0
            
            try:
                resp = self.dce.request(request)
                result_buffer = resp['ResultBuffer']
                if not result_buffer or resp['NumActualRecords'] == 0:
                    break

                for i in range(resp['NumActualRecords']):
                    event_offset = resp['EventDataIndices'][i]['Data']
                    event_size = resp['EventDataSizes'][i]['Data']
                    event_data = result_buffer[event_offset:event_offset + event_size]
                    
                    parsed_event = self.parse_event(event_data)
                    if parsed_event:
                        yield parsed_event['xml_content']
                        
            except Exception as e:
                if 'ERROR_NO_MORE_ITEMS' in str(e) or 'RPC_X_BAD_STUB_DATA' in str(e):
                    break
                raise e

    def parse_event(self, event_data):
        try:
            event_bytes = b''.join(event_data)
            result_set = ResultSet(event_bytes)
            xml_content = result_set.xml()

            return {'xml_content': xml_content}
        except Exception as e:
            print(f"Error parsing event: {str(e)}")
            print(f"Event data (first 50 bytes): {event_bytes[:50].hex()}")
            return None

    def parse_xml(self, xml_content):
        ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        root = ET.fromstring(xml_content)
        event_data = {}
        for elem in root.findall('.//ns:System//*', ns):
            if elem.text and elem.text.strip():
                event_data[elem.tag.split('}')[1]] = elem.text
            for attr_name, attr_value in elem.attrib.items():
                event_data[f"{elem.tag.split('}')[1]}.{attr_name}"] = attr_value
        for data in root.findall('.//ns:EventData/ns:Data', ns):
            name = data.get('Name')
            if name:
                event_data[name] = data.text
        
        return event_data

    def close(self):
        self.dce.disconnect()
