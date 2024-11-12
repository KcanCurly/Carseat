
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class AppLocker:
    def __init__(self, configured: bool, appidsvcstate: str, keyname: str, enforcementmode: str, rules: str):
        self.Configured = configured
        self.AppIdSvcState = appidsvcstate
        self.KeyName = keyname
        self.EnforcementMode = enforcementmode
        self.Rules = rules

def get_app_lockers(wmi_conn):
    wmidata = wmi_conn.wmi_get("SELECT Name, State FROM win32_service WHERE Name = 'AppIDSvc'")
    appIdSvcState = "Service not found"
    enforcementModeStr = ''
    key_name = ''
    rules = []
    for d in wmidata:
        data = wmi_conn.parse_wmi(d)
        appIdSvcState = data['State']

    keys = wmi_conn.get_subkey_names('HKLM', 'Software\\Policies\\Microsoft\\Windows\\SrpV2')
    if keys is not None and len(keys) != 0:
        for k in keys:
            key_name = k
            enforcement_mode = wmi_conn.get_dword_value('HKLM', f'Software\\Policies\\Microsoft\\Windows\\SrpV2\\{k}', 'EnforcementMode')
            if enforcement_mode is None:
                enforcementModeStr = 'not configured'
            elif enforcement_mode == 0:
                enforcementModeStr = 'Audit Mode'
            elif enforcement_mode == 1:
                enforcementModeStr = 'Enforce Mode'
            else:
                enforcementModeStr = f'Unknown value {enforcement_mode}'

            ids = wmi_conn.get_subkey_names('HKLM', f'Software\\Policies\\Microsoft\\Windows\\SrpV2\\{k}')
            for i in ids:
                rule = wmi_conn.get_string_value('HKLM', f"Software\\Policies\\Microsoft\\Windows\\SrpV2\\{k}\\{i}", "Value")
                rules.append(rule)

        yield AppLocker(True, appIdSvcState, key_name, enforcementModeStr, rules)
    else:
        yield AppLocker(False, appIdSvcState, key_name, enforcementModeStr, rules)

def format_results(applocker):
    print(f"  [*] AppIDSvc service is {applocker.AppIdSvcState}\n")
    if applocker.AppIdSvcState != 'Running':
        print("    [*] Applocker is not running because the AppIDSvc is not running\n")

    if not applocker.Configured:
        print("  [*] AppLocker not configured")

    elif applocker.EnforcementMode == 'not configured':
        print(f'    [*] {applocker.KeyName} not configured')

    else:
        print(f'\n    [*] {applocker.KeyName} is in {applocker.EnforcementMode}')
        
        if len(applocker.Rules) == 0:
            print('      [*] No rules')
        else:
            for r in applocker.Rules:
                print(f'      [*] {r}')

def command_base(options):
    command = 'AppLocker'
    description = 'AppLocker settings, if installed'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for applocker in get_app_lockers(wmi_conn):
            if applocker is not None:
                format_results(applocker)
    except KeyboardInterrupt:
        wmi_conn.close()    
    except Exception as e:
        print(e)

    wmi_conn.close()