
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class MappedDrives:
    def __init__(self, localname: str, remotename: str, remotepath: str, status: str, connectionstate: str, persistent: str, username: str, description: str):
        self.LocalName = localname
        self.RemoteName = remotename
        self.RemotePath = remotepath
        self.Status = status
        self.ConnectionState = connectionstate
        self.Persistent = persistent
        self.UserName = username
        self.Description = description

def get_mapped_drives(wmi_conn):
    wmi_data = wmi_conn.wmi_get('SELECT * FROM win32_networkconnection')
    for o in wmi_data:
        data = wmi_conn.parse_wmi(o)
        yield MappedDrives(data['LocalName'], data['RemoteName'], data['RemotePath'], data['Status'], data['ConnectionState'], data['Persistent'], data['UserName'], data['Description'])


def command_base(options):
    command = 'MappedDrives'
    description = 'Users mapped drives (via WMI)'
    command_group = ['user', 'remote']
    wmi_namespace = "//./root/CIMv2"

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    print("Mapped Drives (via WMI)\n")
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for drives in get_mapped_drives(wmi_conn):
            if drives is not None:
                PrintHandler.print_props(drives)
                print()
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()