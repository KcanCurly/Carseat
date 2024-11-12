

from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class WSUS:
    def __init__(self, usewuserver: str, server: str, alternateserver: str, statisticsserver: str):
        self.UseWUServer = usewuserver
        self.Server = server
        self.AlternateServer = alternateserver
        self.StatisticsServer = statisticsserver

def get_wsus(wmi_conn):
    use_wsus = wmi_conn.get_dword_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU', 'UseWUServer') == 1
    wuserver = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate', 'WUServer')
    us_serv = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate', 'UpdateServiceUrlAlternate')
    st_serv = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate', 'WUStatusServer')

    yield WSUS(use_wsus, wuserver, us_serv, st_serv)

def command_base(options):
    command = 'WSUS'
    description = 'Windows Server Update Services (WSUS) settings, if applicable'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"
    
    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for wsus in get_wsus(wmi_conn):
            if wsus is not None:
                PrintHandler.print_props(wsus)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()
