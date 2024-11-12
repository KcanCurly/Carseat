
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class PuttyHostKeys:
    def __init__(self, sid: str, hostkeys: list):
        self.Sid = sid
        self.HostKeys = hostkeys

def get_putty_host_keys(wmi_conn):
    sids = wmi_conn.get_user_sids()

    for sid in sids:
        if not sid.startswith('S-1-5') or sid.endswith('_Classes'):
            continue
        host_keys = wmi_conn.get_registry_value('HKU', f'{sid}\\Software\\SimonTatham\\PuTTY\\SshHostKeys\\')

        if host_keys is None or len(host_keys) == 0:
            continue
        keys = []
        for kvp, val in host_keys.items():
            keys.append(kvp)

        yield PuttyHostKeys(sid, keys)

def format_results(phk):
    print(f'  {phk.Sid} :')

    for key in phk.HostKeys:
        print(f'    {key}')
    print()

def command_base(options):
    command = 'PuttyHostKeys'
    description = 'Saved Putty SSH host keys'
    command_group = ['user', 'remote']
    wmi_namespace = "//./root/CIMv2"
    
    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for phk in get_putty_host_keys(wmi_conn):
            if phk is not None:
                format_results(phk)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()