
import logging
import socket
from collections import OrderedDict
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcomrt import DCOMConnection, NULL

class WMIHandler:
    def __init__(self, target, namespace, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None):
        self.dcom = None
        self.iWbemServices = None
        self.target = target
        self.namespace = namespace
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

    def connect(self):
        try:
            self.dcom = DCOMConnection(self.target, self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey, oxidResolver=True, doKerberos=self.doKerberos, kdcHost=self.kdcHost)
            iInterface = self.dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            self.iWbemServices = iWbemLevel1Login.NTLMLogin(self.namespace, NULL, NULL)
        except socket.error as e:
            logging.error(f"Couldn't connect {self.target}. Error: {str(e)}")
            exit(0)
        except KeyboardInterrupt:
            self.close()

    def query(self, wql):
        try:
            iEnumWbemClassObject = self.iWbemServices.ExecQuery(wql)
            return iEnumWbemClassObject
        except Exception as e:
            if str(e).find('S_FALSE') < 0:
                print(e)
            return

    def get_wmi_object(self, wql):
        if not self.iWbemServices:
            raise Exception("WMI service not initialized. Call connect() first.")
        try:
            iEnumWbemClassObject = self.iWbemServices.ExecQuery(wql)
            while True:
                try:
                    objects = iEnumWbemClassObject.Next(0xffffffff, 1)
                    if len(objects) == 0:
                        break
                    for obj in objects:
                        yield obj
                except wmi.DCERPCSessionError as e:
                    if str(e).find('S_FALSE') < 0:
                        print(f"WMI query iteration error: {e}")
                    break
        except Exception as e:
            print(f"Error executing WMI query: {e}")

    def full_query(self, wql):
        if not self.iWbemServices:
            raise Exception("WMI service not initialized. Call connect() first.")
        try:
            iEnumWbemClassObject = self.iWbemServices.ExecQuery(wql)
            while True:
                try:
                    objects = iEnumWbemClassObject.Next(0xffffffff, 1)
                    if len(objects) == 0:
                        break
                    for obj in objects:
                        yield obj.getProperties()
                except wmi.DCERPCSessionError as e:
                    if str(e).find('S_FALSE') < 0:
                        print(f"WMI query iteration error: {e}")
                    break
        except Exception as e:
            print(f"Error executing WMI query: {e}")

    def wmi_get(self, wql):
        try:
            return list(self.full_query(wql))
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            if str(e).find('S_FALSE') < 0:
                raise
            return []

    def parse_wmi_key(self, ordered_dict, wmi_keys):
        result = {}
        for key in wmi_keys:
            if key in ordered_dict:
                result[key] = ordered_dict[key].get('value', None)
            else:
                result[key] = None
        print(result)
        return result

    def parse_wmi(self, ordered_dict):
        def parse_value(value):
            if isinstance(value, wmi.ENCODING_UNIT):
                return self.parse_wmi_object(str(value))
            elif isinstance(value, list):
                return [parse_value(item) for item in value]
            elif isinstance(value, dict):
                return {k: parse_value(v) for k, v in value.items()}
            else:
                return value
        #output = {key: parse_value(value['value']) for key, value in ordered_dict.items()}
        output = {}
        for key, value in ordered_dict.items():
            od_value = value['value']
            parsed = parse_value(od_value)
            if not isinstance(parsed, str):
                parsed = parse_value(parsed)
            output[key] = parse_value(parsed)
        return output

    def parse_wmi_object(self, hex_string):
        output = {}
        try:
            encoding_unit_bytes = bytes.fromhex(hex_string)
        except ValueError as e:
            raise ValueError(f"Invalid hex string: {str(e)}")

        encoding_unit = wmi.ENCODING_UNIT(encoding_unit_bytes)
        
        result = {
            'Signature': encoding_unit['Signature'],
            'ObjectEncodingLength': encoding_unit['ObjectEncodingLength'],
            'ObjectBlock': {}
        }
        
        object_block = encoding_unit['ObjectBlock']
        if object_block != NULL:
            result['ObjectBlock']['ObjectFlags'] = object_block['ObjectFlags']
            if 'InstanceType' in object_block.fields:
                instance_type = object_block.fields['InstanceType']
                if instance_type != NULL:
                    instance_data = {
                        'EncodingLength': instance_type['EncodingLength'],
                        'InstanceFlags': instance_type['InstanceFlags'],
                        'InstanceClassName': instance_type['InstanceClassName']
                    }
                    if 'CurrentClass' in instance_type.fields:
                        current_class = instance_type['CurrentClass']                    
                        if 'ClassPart' in current_class.fields:
                            class_part = current_class['ClassPart']                      
                            try:
                                properties = class_part.getProperties()
                                instance_data['Properties'] = properties
                            except Exception as e:
                                print(f"Error getting properties from ClassPart: {str(e)}")
                    if 'Properties' in instance_data and hasattr(instance_type, 'getValues'):
                        try:
                            values = instance_type.getValues(instance_data['Properties'])
                            instance_data['Values'] = values
                            output = {key: details['value'] for key, details in values.items()}
                        except Exception as e:
                            print(f"Error getting values: {str(e)}")
        return output

    def get_wmi_data(self, iEnum):
        try:
            pEnum = iEnum.Next(0xffffffff,1)[0]
            record = pEnum.getProperties()
            return record.items()
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            if str(e).find('S_FALSE') < 0:
                raise

    def get_subkey_names(self, hive, key_path):
        hive_num = self._get_hive_num(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.EnumKey(hive_num, key_path)
        
        if ret_vals.ReturnValue == 0:
            return ret_vals.sNames or []
        return []

    def get_string_value(self, hive, key_path, value_name):
        hive_num = self._get_hive_num(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.GetStringValue(hive_num, key_path, value_name)
        
        if ret_vals.ReturnValue == 0:
            return ret_vals.sValue
        return None

    def get_binary_value(self, hive, key_path, value_name):
        hive_num = self._get_hive_num(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.GetBinaryValue(hive_num, key_path, value_name)
        
        if ret_vals.ReturnValue == 0:
            return bytes(ret_vals.uValue)
        return None

    def get_dword_value(self, hive, key_path, value_name):
        try:
            hive_num = self._get_hive_num(hive)
            classObject, _ = self.iWbemServices.GetObject('StdRegProv')
            ret_vals = classObject.GetDWORDValue(hive_num, key_path, value_name)
            if hasattr(ret_vals, 'ReturnValue'):
                if ret_vals.ReturnValue == 0:
                    if hasattr(ret_vals, 'uValue'):
                        return ret_vals.uValue
                    else:
                        return None
                else:
                    return None         
            return None
        except Exception as e:
            return None

    def get_registry_value(self, hive, key_path):
        hive_num = self._get_hive_num(hive)
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.EnumValues(hive_num, key_path)
        
        if ret_vals.ReturnValue != 0:
            return {}

        results = {}
        value_names = ret_vals.sNames or []
        value_types = ret_vals.Types or []

        for name, type in zip(value_names, value_types):
            try:
                if type == 1:  # String
                    value = classObject.GetStringValue(hive_num, key_path, name)
                    val = value.sValue if hasattr(value, 'sValue') else None
                elif type == 2:  # Expanded String
                    value = classObject.GetExpandedStringValue(hive_num, key_path, name)
                    val = value.sValue if hasattr(value, 'sValue') else None
                elif type == 3:  # Binary
                    value = classObject.GetBinaryValue(hive_num, key_path, name)
                    val = bytes(value.uValue) if hasattr(value, 'uValue') else None
                elif type == 4:  # DWORD
                    value = classObject.GetDWORDValue(hive_num, key_path, name)
                    val = value.uValue if hasattr(value, 'uValue') else None
                elif type == 7:  # Multi-String
                    value = classObject.GetMultiStringValue(hive_num, key_path, name)
                    val = value.sValue if hasattr(value, 'sValue') else None
                elif type == 11:  # QWORD
                    value = classObject.GetQWORDValue(hive_num, key_path, name)
                    val = value.uValue if hasattr(value, 'uValue') else None
                else:
                    continue

                if value.ReturnValue == 0 and val is not None:
                    results[name] = val
                
            except Exception as e:
                continue
        return results

    def get_env_var(self, variable):
        query = f"SELECT VariableValue from win32_environment WHERE name='{variable}' AND UserName='<SYSTEM>'"
        odict =  self.wmi_get(query)
        for data in odict:
            env_var = self.parse_wmi(data)
        return env_var['VariableValue']
    
    def get_user_sids(self):
        hive_num = self._get_hive_num('HKU')
        classObject, _ = self.iWbemServices.GetObject('StdRegProv')
        ret_vals = classObject.EnumKey(hive_num, '')
        
        if ret_vals.ReturnValue == 0:
            return ret_vals.sNames or []
        return []

    def _get_hive_num(self, hive):
        hive_map = {
            'HKCC': 0x80000005,
            'HKU': 0x80000003,
            'HKLM': 0x80000002,
            'HKCU': 0x80000001,
            'HKCR': 0x80000000,
        }
        return hive_map.get(hive, 0x80000002)

    def close(self):
        if self.iWbemServices:
            self.iWbemServices.RemRelease()
        if self.dcom:
            self.dcom.disconnect()

