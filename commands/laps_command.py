
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class LAPS:
    def __init__(self, admpwdenabled: str, lapsadminaccountname: str, lapspasswordcomplexity:str, lapspasswordlength: str, lapspwdexpirationprotectionenabled: str):
        self.AdmPwdEnabled = admpwdenabled
        self.LAPSAdminAccountName = lapsadminaccountname
        self.LAPSPasswordComplexity = lapspasswordcomplexity
        self.LAPSPasswordLength = lapspasswordlength
        self.LapsPwdExpirationProtectionEnabled = lapspwdexpirationprotectionenabled

def get_laps(wmi_conn):
    adm_pwd_enabled = wmi_conn.get_string_value('HKLM', 'Software\\Policies\\Microsoft Services\\AdmPwd', 'AdmPwdEnabled')

    if adm_pwd_enabled is not None and adm_pwd_enabled != '':
        laps_admin_account_name = wmi_conn.get_string_value('HKLM', 'Software\\Policies\\Microsoft Services\\AdmPwd', 'AdminAccountName')
        laps_password_complexity = wmi_conn.get_string_value('HKLM', 'Software\\Policies\\Microsoft Services\\AdmPwd', 'PasswordComplexity')
        laps_password_length = wmi_conn.get_string_value('HKLM', 'Software\\Policies\\Microsoft Services\\AdmPwd', 'PasswordLength')
        laps_pwd_expiration_protection_enabled = wmi_conn.get_string_value('HKLM', 'Software\\Policies\\Microsoft Services\\AdmPwd', 'PwdExpirationProtectionEnabled')
        yield LAPS("1", laps_admin_account_name, laps_password_complexity, laps_password_length, laps_pwd_expiration_protection_enabled)
    else:
        yield LAPS('False', None, None, None, None)

def format_results(laps):
    if laps.AdmPwdEnabled == 'False':
        print('  [*] LAPS not installed')
    else:
        print(f"  {'LAPS Enabled':<37} : {laps.AdmPwdEnabled}")
        print(f"  {'LAPS Admin Account Name':<37} : {laps.LAPSAdminAccountName}")
        print(f"  {'LAPS Password Complexity':<37} : {laps.LAPSPasswordComplexity}")
        print(f"  {'LAPS Password Length':<37} : {laps.LAPSPasswordLength}")
        print(f"  {'LAPS Expiration Protection Enable':<37} : {laps.LapsPwdExpirationProtectionEnabled}")

def command_base(options):
    command = 'LAPS'
    description = 'LAPS settings, if installed'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for laps in get_laps(wmi_conn):
            if laps is not None:
                format_results(laps)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()