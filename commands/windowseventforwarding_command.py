
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class WindowsEventForwarding:
    def __init__(self, key: str, value: str):
        self.Key = key
        self.Value = value

def get_windows_event_forwarding(wmi_conn):
    settings = wmi_conn.get_registry_value('HKLM', 'Software\\Policies\\Microsoft\\Windows\\EventLog\\EventForwarding\\SubscriptionManager')

    if settings is not None:
        for key, value in settings.items():
            if isinstance(value, list) and all(isinstance(x, str) for x in value):
                result = value.join(',')
                print(f'  {key:<30} : {result}')
                yield WindowsEventForwarding(key, result)
            else:
                print(f'  {key:<30} : {value}')
                yield WindowsEventForwarding(key, str(value))

def command_base(options):
    command = 'WindowsEventForwarding'
    description = 'Windows Event Forwarding (WEF) settings via the registry'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"
    
    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for wef in get_windows_event_forwarding(wmi_conn):
            if wef is not None:
                PrintHandler.print_kv(wef)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()
    