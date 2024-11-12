
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class WindowsAutoLogon:
    def __init__(self, defaultdomainname: str, defaultusername: str, defaultpassword: str, altdomainname: str, altusername: str, altpassword: str):
        self.DefaultDomainName = defaultdomainname
        self.DefaultUserName = defaultusername
        self.DefaultPassword = defaultpassword
        self.AltDefaultDomainName = altdomainname
        self.AltDefaultUserName = altusername
        self.AltDefaultPassword = altpassword

def get_windows_auto_logon(wmi_conn):
    default_domain_name = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'DefaultDomainName')
    default_user_name = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'DefaultUserName')
    default_password = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'DefaultPassword')
    alt_domain_name = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'AltDefaultDomainName')
    alt_user_name = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'AltDefaultUserName')
    alt_password = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'AltDefaultPassword')

    yield WindowsAutoLogon(default_domain_name, default_user_name, default_password, alt_domain_name, alt_user_name, alt_password)

def command_base(options):
    command = 'WindowsAutoLogon'
    description = 'Registry autologon information'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"
    
    domain, username, password, address = parse_target(options.target)
    
    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for autologon in get_windows_auto_logon(wmi_conn):
            if autologon is not None:
                PrintHandler.print_props(autologon)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()