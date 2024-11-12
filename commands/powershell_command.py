
import os
from lib import WMIHandler
from lib import SMBHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class PowerShell:
    def __init__(self, installedclrversions: list, installedversions: list, transcriptionlogging: str, transcriptioninvocationlogging: str, transcriptiondirectory: str, modulelogging: str, modulenames: str, scriptblocklogging: str, scriptblockinvocationlogging: str, ossupportamsi: str):
        self.InstalledCLRVersions = installedclrversions
        self.InstalledVersions = installedversions
        self.TranscriptionLogging = transcriptionlogging
        self.TranscriptionInvocationLogging = transcriptioninvocationlogging
        self.TranscriptionDirectory = transcriptiondirectory
        self.ModuleLogging = modulelogging
        self.ModuleNames = modulenames
        self.ScriptBlockLogging = scriptblocklogging
        self.ScriptBlockInvocationLogging = scriptblockinvocationlogging
        self.OsSupportsAmsi = ossupportamsi

def get_version_from_string(version):
    class Version:
        def __init__(self, version_str: str):
            parts = version_str.split('.')
            self.major = int(parts[0]) if len(parts) > 0 else 0
            self.minor = int(parts[1]) if len(parts) > 1 else 0
            self.build = int(parts[2]) if len(parts) > 2 else 0
            
    version_str = version.split('-')[0]
    return Version(version_str)

def get_os_version(wmi_conn):
    wmi_data = wmi_conn.wmi_get('SELECT Version FROM Win32_OperatingSystem')
    try:
        for d in wmi_data:
            data = wmi_conn.parse_wmi(d)
            return data['Version']
    except Exception as e:
        pass
    return ''

def get_powershell_versions(wmi_conn):
    versions = []
    ps_v2 = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine', 'PowerShellVersion')
    if ps_v2 is not None:
        versions.append(ps_v2)

    ps_v4p = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine', 'PowerShellVersion')
    if ps_v4p is not None:
        versions.append(ps_v4p)

    return versions

def get_pscore_versions(wmi_conn):
    versions = []
    keys = wmi_conn.get_subkey_names('HKLM','SOFTWARE\\Microsoft\\PowerShellCore\\InstalledVersions\\')
    for key in keys:
        ver = wmi_conn.get_string_value('HKLM', f'SOFTWARE\\Microsoft\\PowerShellCore\\InstalledVersions\\{key}', 'SemanticVersion')
        if ver is not None:
            versions.append(ver)
    return versions

def get_clr_versions(smb_conn):
    versions = []
    share = "C$"
    net_path = '\\Windows\\Microsoft.Net\\Framework\\'
    dirs = smb_conn.list_directory(share, net_path)
    for dir in dirs:
        path = f'{net_path}{dir.get_longname()}'
        if smb_conn.file_exists(share, f'{path}\\System.dll'):
            version = os.path.basename(path.rstrip(os.path.sep)).lstrip('v')
            versions.append(version)

    return versions


def get_powershell(wmi_conn, smb_conn):
    installed_versions = []
    installed_clr = []
    installed_versions.extend(get_powershell_versions(wmi_conn))
    installed_versions.extend(get_pscore_versions(wmi_conn))
    installed_clr.extend(get_clr_versions(smb_conn))

    transcription_logging = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription', 'EnableTranscripting') == '1'
    transcription_invo_log = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription', 'EnableInvocationHeader') == '1'
    transcription_directory = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription', 'OutputDirectory')
    module_logging = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging', 'EnableModuleLogging') == '1'
    module_names = wmi_conn.get_registry_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\ModuleNames')
    script_block_logging = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging', 'EnableScriptBlockLogging') == '1'
    script_block_invocation_log = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging', 'EnableScriptBlockInvocationLogging') == '1'

    os_ver_major = get_os_version(wmi_conn).split('.')[0]
    os_sup_amsi = int(os_ver_major) >= 10

    yield PowerShell(installed_clr, installed_versions, transcription_logging, transcription_invo_log, transcription_directory, module_logging, module_names, script_block_logging, script_block_invocation_log, os_sup_amsi)

def format_results(powershell):
    versions = [get_version_from_string(v) for v in powershell.InstalledVersions]
    lowest_version = min(versions, key=lambda v: (v.major, v.minor, v.build))
    highest_version = max(versions, key=lambda v: (v.major, v.minor, v.build))


    print('\n  Installed CLR Versions')
    for var in powershell.InstalledCLRVersions:
        print(f'      {var}')
    
    print('\n  Installed PowerShell Versions')
    for var in powershell.InstalledVersions:
        print(f'      {var}')
        if var == '2.0' and not '2.0.50727' in powershell.InstalledCLRVersions:
            print("        [!] Version 2.0.50727 of the CLR is not installed - PowerShell v2.0 won't be able to run.")

    print("\n  Transcription Logging Settings")
    print(f"      Enabled            : {powershell.TranscriptionLogging}")
    print(f"      Invocation Logging : {powershell.TranscriptionInvocationLogging}")
    print(f"      Log Directory      : {powershell.TranscriptionDirectory}")

    print("\n  Module Logging Settings")
    print(f"      Enabled             : {powershell.ModuleLogging}")
    print("      Logged Module Names :")
    if powershell.ModuleNames is not None:
        for m in powershell.ModuleNames:
            print(f'          {m}')

    if powershell.ModuleLogging:
        if lowest_version.major < 3:
            print('        [!] You can do a PowerShell version downgrade to bypass the logging.')
        if highest_version.major < 3:
            print('        [!] Module logging is configured. Logging will not occur, however, because it requires PSv3.')

    print('\n  Script Block Logging Settings')
    print(f'      Enabled            : {powershell.ScriptBlockLogging}')
    print(f'      Invocation Logging : {powershell.ScriptBlockInvocationLogging}')
    if powershell.ScriptBlockLogging:
        if highest_version.major < 5:
            print('        [!] Script block logging is configured. Logging will not occur, however, because it requires PSv5."')
        if lowest_version.major < 5:
            print('        [!] You can do a PowerShell version downgrade to bypass the logging.')
    
    print('\n  Anti-Malware Scan Interface (AMSI)')
    print(f'      OS Supports AMSI: {powershell.OsSupportsAmsi}')
    if powershell.OsSupportsAmsi and lowest_version.major < 3:
        print('        [!] You can do a PowerShell version downgrade to bypass AMSI.')

def command_base(options):
    command = 'PowerShell'
    description = 'PowerShell versions and security settings'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        smb_conn = SMBHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        for ps in get_powershell(wmi_conn, smb_conn):
            if ps is not None:
                format_results(ps)
    except KeyboardInterrupt:
        wmi_conn.close()
        smb_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()
    smb_conn.close()