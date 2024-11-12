
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class SCCMClient:
    def __init__(self, server: str, sitecode: str, productversion: str, lastsuccessfulinstallparams: str):
        self.Server = server
        self.SiteCode = sitecode
        self.ProductVersion = productversion
        self.LastSuccessfulInstallParams = lastsuccessfulinstallparams

def get_sccm(wmi_conn):
    last_valid = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Microsoft\\CCMSetup', 'LastValidMP')
    site_code = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Microsoft\\SMS\\Mobile Client', 'AssignedSiteCode')
    prod_ver = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Microsoft\\SMS\\Mobile Client', 'ProductVersion')
    successful_install_param = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Microsoft\\SMS\\Mobile Client', 'LastSuccessfulInstallParams')

    yield SCCMClient(last_valid, site_code, prod_ver, successful_install_param)

def command_base(options):
    command = 'SCCM'
    description = 'System Center Configuration Manager (SCCM) settings, if applicable'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"
    
    domain, username, password, address = parse_target(options.target)
    
    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for sccm in get_sccm(wmi_conn):
            if sccm is not None:
                PrintHandler.print_props(sccm)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()