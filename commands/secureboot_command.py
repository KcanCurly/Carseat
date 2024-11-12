
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class SecureBoot:
    def __init__(self, enabled: bool, publisher: str, version: str):
        self.Enabled = enabled
        self.Publisher = publisher
        self.Version = version

def get_secure_boot(wmi_conn):
    uefi_state = wmi_conn.get_dword_value('HKLM', 'SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State', 'UEFISecureBootEnabled')
    if uefi_state is None:
        uefi_state = 0
    
    policy_publisher = wmi_conn.get_string_value('HKLM', 'SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State', 'PolicyPublisher')
    policy_version = wmi_conn.get_string_value('HKLM', 'SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State', 'PolicyVersion')

    yield SecureBoot(True if uefi_state == 1 else False, policy_publisher, policy_version)

def command_base(options):
    command = 'SecureBoot'
    description = 'Secure Boot configuration'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"
    
    domain, username, password, address = parse_target(options.target)
    
    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for boot in get_secure_boot(wmi_conn):
            if boot is not None:
                PrintHandler.print_props(boot)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()