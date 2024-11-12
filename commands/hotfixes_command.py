
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class HotFix:
    def __init__(self, hotfixid: str, installedonutc: str, description: str, installedby: str):
        self.HotFixID = hotfixid
        self.InstalledOnUTC = installedonutc
        self.Description = description
        self.InstalledBy = installedby

def get_hotfixes(wmi_conn):
    print("Enumerating Windows Hotfixes. For *all* Microsoft updates, use the 'MicrosoftUpdates' command.\r\n")
    try:
        fix_data = wmi_conn.wmi_get('SELECT * FROM Win32_QuickFixEngineering')
    except Exception as e:
        return None

    for fixes in fix_data:
        data = wmi_conn.parse_wmi(fixes)
        yield HotFix(data['HotFixID'], data['InstalledOn'], data['Description'], data['InstalledBy'])


def format_results(hotfix):
    print(f'  {hotfix.HotFixID:<10} {hotfix.InstalledOnUTC:<22} {hotfix.Description:<30} {hotfix.InstalledBy}')


def command_base(options):
    command = 'Hotfixes'
    description = 'Hotfixes'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"
    

    domain, username, password, address = parse_target(options.target)
    
    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for hotfix in get_hotfixes(wmi_conn):
            if hotfix is not None:
                format_results(hotfix)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()