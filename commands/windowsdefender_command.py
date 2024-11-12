
import uuid
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class AsrRule:
    def __init__(self, rule: uuid, state: int):
        self.Rule = rule
        self.State = state

class AsrSettings:
    def __init__(self, enabled: bool):
        self.Enabled = enabled
        self.Rules = []
        self.Exclusions = []

class WindowsDefendersettings:
    def __init__(self):
        self.PathExclusions = []
        self.PolicyManagerPathExclusions = []
        self.ProcessExclusions = []
        self.ExtensionExclusions = []
        self.AsrSettings = None

    def get_defender_settings(self, wmi_conn, reg_key):
        exclusion_path = wmi_conn.get_registry_value('HKLM', f'{reg_key}\\Exclusions\\Paths')
        for k in exclusion_path:
            self.PathExclusions.append(k)
        
        excluded_path = wmi_conn.get_string_value('HKLM', f'{reg_key}\\Policy Manager', 'ExcludedPaths')
        if excluded_path is not None:
            for s in exclusion_path.split('|'):
                self.PolicyManagerPathExclusions.append(s)
        
        proc_exclusions_data = wmi_conn.get_registry_value('HKLM', f'{reg_key}\\Exclusions\\Processes')
        for k in proc_exclusions_data:
            self.ProcessExclusions.append(k)

        extension_exclusion_data = wmi_conn.get_registry_value('HKLM', f'{reg_key}\\Exclusions\\Extensions')
        for k in extension_exclusion_data:
            self.ExtensionExclusions.append(k)

        asr_enabled = wmi_conn.get_dword_value('HKLM', f'{reg_key}\\Windows Defender Exploit Guard\\ASR', 'ExploitGuard_ASR_Rules')
        self.AsrSettings = AsrSettings(asr_enabled is not None and asr_enabled != 0)

        asr_rules = wmi_conn.get_registry_value('HKLM', f'{reg_key}\\Windows Defender Exploit Guard\\ASR\\Rules')
        for val in asr_rules:
            self.AsrSettings.Rules.append(AsrRule(uuid.UUID(val['Key']), int(val['Value'])))
        
        asr_exclusions = wmi_conn.get_registry_value('HKLM', f'{reg_key}\\Windows Defender Exploit Guard\\ASR\\ASROnlyExclusions')
        for val in asr_exclusions:
            self.AsrSettings.Exclusions.append(val.key)

        return self

class WindowsDefender:
    def __init__(self, localsettings: WindowsDefendersettings, grouppolicysettings: WindowsDefendersettings):
        self.LocalSettings = localsettings
        self.GroupPolicySettings = grouppolicysettings

def get_windows_defender(wmi_conn):
    local_wd = WindowsDefendersettings()
    local_settings = local_wd.get_defender_settings(wmi_conn, 'SOFTWARE\\Microsoft\\Windows Defender')
    group_wd = WindowsDefendersettings()
    group_settings = group_wd.get_defender_settings(wmi_conn, 'SOFTWARE\\Policies\\Microsoft\\Windows Defender')
    yield WindowsDefender(local_settings, group_settings)

def asr_guids():
    return {
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a": "Block all Office applications from creating child processes",
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc": "Block execution of potentially obfuscated scripts",
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "Block Win32 API calls from Office macro	",
        "3b576869-a4ec-4529-8536-b80a7769e899": "Block Office applications from creating executable content	",
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": "Block Office applications from injecting code into other processes",
        "d3e037e1-3eb8-44c8-a917-57927947596d": "Block JavaScript or VBScript from launching downloaded executable content",
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "Block executable content from email client and webmail",
        "01443614-cd74-433a-b99e-2ecdc07bfc25": "Block executable files from running unless they meet a prevalence, age, or trusted list criteria",
        "c1db55ab-c21a-4637-bb3f-a12568109d35": "Use advanced protection against ransomware",
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": "Block credential stealing from the Windows local security authority subsystem (lsass.exe)",
        "d1e49aac-8f56-4280-b9ba-993a6d77406c": "Block process creations originating from PSExec and WMI commands",
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": "Block untrusted and unsigned processes that run from USB",
        "26190899-1602-49e8-8b27-eb1d0a1ce869": "Block Office communication applications from creating child processes",
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": "Block Adobe Reader from creating child processes",
        "e6db77e5-3df2-4cf1-b95a-636979351e5b": "Block persistence through WMI event subscription",
    }

def format_results(defender):
    print('Locally-defined Settings:')
    display_defender_settings(defender.LocalSettings)
    print('\n\n\nGPO-defined Settings:')
    display_defender_settings(defender.GroupPolicySettings)

def display_defender_settings(settings):
    path_exclusions = settings.PathExclusions
    process_exclusions = settings.ProcessExclusions
    extension_exclusions = settings.ExtensionExclusions
    asr_settings = settings.AsrSettings

    if len(path_exclusions) != 0:
        print('\n  Path Exclusions:')
        for path in path_exclusions:
            print(f'    {path}')

    if len(path_exclusions) != 0:
        print('\n  PolicyManagerPathExclusions:')
        for path in path_exclusions:
            print(f'    {path}')

    if len(process_exclusions) != 0:
        print('\n  Process Exclusions')
        for proc in process_exclusions:
            print(f'    {proc}')

    if len(extension_exclusions) != 0:
        print('\n  Extension Exclusions')
        for ext in extension_exclusions:
            print(f'    {ext}')

    if asr_settings.Enabled:
        print('\n  Attack Surface Reduction Rules:\n')
        print(f'    {"State":<10} Rule\n')
        for rule in asr_settings.Rules:
            state = None
            if rule.State == 0:
                state = 'Disabled'
            elif rule.State == 1:
                state = 'Blocked'
            elif rule.State == 2:
                state = 'Audited'
            else:
                state = f'{rule.State} - Unknown'

            asr_rule = asr_guids().get(str(rule.Rule), f"{rule.Rule} - Please report this")
            print(f'    {state:<10} {asr_rule}')

    if len(asr_settings.Exclusions) > 0:
        print('\n  ASR Exclusions:')
        for exclusion in asr_settings.Exclusions:
            print(f'    {exclusion}')

def command_base(options):
    command = 'WindowsDefender'
    description = 'Windows Defender settings (including exclusion locations)'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"
    
    domain, username, password, address = parse_target(options.target)
    
    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for defender in get_windows_defender(wmi_conn):
            if defender is not None:
                format_results(defender)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()
    