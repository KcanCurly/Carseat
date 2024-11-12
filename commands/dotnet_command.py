

from lib import WMIHandler
from lib import SMBHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class DotNet:
    def __init__(self, installedclrversions: str, installeddotnetversions: str, ossupportsamsi: str):
        self.InstalledCLRVersions = installedclrversions
        self.InstalledDotNetVersions = installeddotnetversions
        self.OsSupportsAmsi = ossupportsamsi

def get_clr_versions(smb_conn):
    installed_clr = []
    share = "C$"
    path = "\\Windows\\Microsoft.Net\\Framework"

    if smb_conn.connect():
        dirs = smb_conn.list_directory(share, path)
        for d in dirs:
            if d.is_directory():
                if d.get_longname() == '.' or d.get_longname() == '..':
                    continue
                sysdll = f'{path}\\{d.get_longname()}\\System.dll'
                if smb_conn.file_exists(share, sysdll):
                    location = str(d.get_longname())
                    installed_clr.append(location.strip('v'))

    return installed_clr

def get_os_version(wmi_conn):
    os_query = wmi_conn.wmi_get('SELECT Version FROM Win32_OperatingSystem')

    for o in os_query:
        data = wmi_conn.parse_wmi(o)
    
    return data['Version']

def get_dotnet(wmi_conn, smb_conn):
    installed_dotnet_versions = []
    installed_clr_versions = get_clr_versions(smb_conn)

    dot_net_threefive = wmi_conn.get_string_value('HKLM ', r'SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5', 'Version')
    if dot_net_threefive is not None:
        installed_dotnet_versions.append(dot_net_threefive)
    dot_net_four = wmi_conn.get_string_value('HKLM ', r'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full', 'Version')
    if dot_net_four is not None:
        installed_dotnet_versions.append(dot_net_four)

    os_version = get_os_version(wmi_conn).split('.')[0]
    os_amsi = int(os_version) >= 10
    yield DotNet(installed_clr_versions, installed_dotnet_versions, os_amsi)

def get_version(versions, find='lowest'):
    def parse_version(version):
        return tuple(map(int, version.split('.')))
    if find == 'lowest':
        return min(versions, key=parse_version)
    elif find == 'highest':
        return max(versions, key=parse_version)
    else:
        raise ValueError("find must be either 'lowest' or 'highest'")
    
def format_results(dotnet_obj):
    lowest_version = get_version(dotnet_obj.InstalledDotNetVersions, find='lowest')
    highest_version = get_version(dotnet_obj.InstalledDotNetVersions, find='highest')
    dn_support_amsi = int(highest_version.split('.')[0]) >= 4 and int(highest_version.split('.')[1]) >= 8

    print('  Installed CLR Versions')
    for v in dotnet_obj.InstalledCLRVersions:
        print(f'      {v}')

    print('\n  Installed .NET Versions')
    for vv in dotnet_obj.InstalledDotNetVersions:
        print(f'      {vv}')

    print('\n  Anti-Malware Scan Interface (AMSI)')
    print(f'      OS supports AMSI           : {dotnet_obj.OsSupportsAmsi}')
    print(f'     .NET version support AMSI   : {dn_support_amsi}')

    if int(highest_version.split('.')[0]) == 4 and int(highest_version.split('.')[1]) >= 8:
        print('        [!] The highest .NET version is enrolled in AMSI!')

    if dotnet_obj.OsSupportsAmsi and dn_support_amsi and int(lowest_version.split('.')[0]) == 3 or int(lowest_version.split('.')[0]) == 4 and int(lowest_version.split('.')[1]) < 8:
        print(f'        [*] You can invoke .NET version {lowest_version.split('.')[0]}.{lowest_version.split('.')[1]} to bypass AMSI.')

def command_base(options):
    command = 'DotNet'
    description = 'DotNet versions'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        smb_conn = SMBHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        for dotnet_info in get_dotnet(wmi_conn, smb_conn):
            if dotnet_info is not None:
                format_results(dotnet_info)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()
    smb_conn.close()