
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class LocalSecurityAuthority:
    def __init__(self, key: str, value: str):
        self.Key = key
        self.Value = value

def get_lsa_settings(wmi_conn):
    settings = wmi_conn.get_registry_value('HKLM', 'SYSTEM\\CurrentControlSet\\Control\\Lsa')
    if settings is not None and len(settings) != 0:
        for key, value in settings.items():
            if isinstance(value, list) and all(isinstance(x, str) for x in value):
                result = ",".join(value)
                yield LocalSecurityAuthority(key, result)
            
            elif isinstance(value, bytes) or (isinstance(value, list) and all(isinstance(x, bytes) for x in value)):
                if isinstance(value, list):
                    value = bytes(value)
                result = value.hex('-').upper()
                yield LocalSecurityAuthority(key, result)
            else:
                yield LocalSecurityAuthority(key, value)

def command_base(options):
    command = 'LSASettings'
    description = 'LSA settings (including auth packages)'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for settings in get_lsa_settings(wmi_conn):
            if settings is not None:
                PrintHandler.print_kv(settings)
        print()
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()