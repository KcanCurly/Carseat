
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target


class NetworkShares:
    def __init__(self, name: str, path: str, description: str, type: str):
        self.Name = name
        self.Path = path
        self.Description = description
        self.Type = type

def get_network_shares(wmi_conn):
    type_dict = {
        0: "Disk Drive",
        1: "Print Queue",
        2: "Device ",
        3: "IPC",
        2147483648: "Disk Drive Admin",
        2147483649: "Print Queue Admin",
        2147483650: "Device Admin",
        2147483651: "IPC Admin",
    }
    wmi_data = wmi_conn.wmi_get('SELECT * FROM Win32_Share')
    for shares in wmi_data:
        data = wmi_conn.parse_wmi(shares)
        types = type_dict.get(int(data['Type']))
        yield NetworkShares(data['Name'], data['Path'], data['Description'], types)

def command_base(options):
    command = 'NetworkShares'
    description = 'Network shares exposed by the machine (via WMI)'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for shares in get_network_shares(wmi_conn):
            if shares is not None:
                PrintHandler.print_props(shares)
                print()
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()