
from enum import IntEnum
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class VBS(IntEnum):
    NOT_ENABLED = 0
    ENABLED_NOT_RUNNING = 1
    ENABLED_AND_RUNNING = 2

class CredGuard:
    def __init__(self, virtualizationbasedsecuritystatus: VBS, configured: bool, running: bool):
        self.VirtualizationBasedSecurityStatus = virtualizationbasedsecuritystatus
        self.Configured = configured
        self.Running = running

def get_cred_guard(wmi_conn):
    try:
        wmi_data = wmi_conn.wmi_get('SELECT * FROM Win32_DeviceGuard')
    except Exception as e:
        print(e)
        return
    
    for cg in wmi_data:
        data = wmi_conn.parse_wmi(cg)

        vbs_setting = VBS(0).name
        configured = False
        running = False

        if data['VirtualizationBasedSecurityStatus']:
            vbs_setting = VBS(data['VirtualizationBasedSecurityStatus']).name
        
        if 1 in data['SecurityServicesConfigured']:
            configured = True

        if 1 in data['SecurityServicesRunning']:
            running = True

        yield CredGuard(vbs_setting , configured, running)

def command_base(options):
    command = 'CredGuard'
    description = 'CredentialGuard configuration'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/Microsoft/Windows/DeviceGuard"
    
    domain, username, password, address = parse_target(options.target)
    
    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for res in get_cred_guard(wmi_conn):
            if res is not None:
                PrintHandler.print_props(res)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()
    