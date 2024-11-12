
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class AuditPolicy:
    def __init__(self, key: str, value: str):
        self.Key = key
        self.Value = value

def get_audit_policy(wmi_conn):
    settings = wmi_conn.get_registry_value('HKLM', 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit')

    if settings is None:
        return None

    for k, v in settings.items():
        if isinstance(settings, list) and all(isinstance(item, str) for item in settings):
            result = ",".join(v)
            yield AuditPolicy(k, result)
        else:
            yield AuditPolicy(k, v)
        
def command_base(options):
    command = 'AuditPolicyRegistry'
    description = 'Audit settings via the registry'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"
    
    domain, username, password, address = parse_target(options.target)
    
    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for aps in get_audit_policy(wmi_conn):
            if aps is not None:
                PrintHandler.print_kv(aps)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()