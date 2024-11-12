
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class RDPSavedConnection:
    def __init__(self, sid: str, connections: list):
        self.Sid = sid
        self.Connections = connections

class RDPConnection:
    def __init__(self, remotehost: str, usernamehint: str):
        self.RemoteHost = remotehost
        self.UserNameHint = usernamehint

def get_rdp_saved_connections(wmi_conn):
    sids = wmi_conn.get_user_sids()

    for sid in sids:
        if not sid.startswith('S-1-5') or sid.endswith('_Classes'):
            continue

        subkeys = wmi_conn.get_subkey_names('HKU', f'{sid}\\Software\\Microsoft\\Terminal Server Client\\Servers')

        if not subkeys or len(subkeys) <= 0:
            continue

        connections = []
        for host in subkeys:
            user_hint = wmi_conn.get_string_value('HKU', f'{sid}\\Software\\Microsoft\\Terminal Server Client\\Servers\\{host}', 'UsernameHint')

            connection = RDPConnection(host, user_hint)
            connections.append(connection)
        yield RDPSavedConnection(sid, connections)

def format_results(rdp):
    if len(rdp.Connections) > 0:
        print(f'Saved RDP Connection Information ({rdp.Sid})\n')
        print("  RemoteHost                         UsernameHint")
        print("  ----------                         ------------")

        for conn in rdp.Connections:
            print(f'  {conn.RemoteHost:<34} {conn.UserNameHint}')
        print()

def command_base(options):
    command = 'RDPSavedConnections'
    description = 'Saved RDP connections stored in the registry'
    command_group = ['user', 'remote']
    wmi_namespace = "//./root/CIMv2"
    
    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for conns in get_rdp_saved_connections(wmi_conn):
            if conns is not None:
                format_results(conns)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()