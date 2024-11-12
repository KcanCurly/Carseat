
from datetime import datetime, timezone
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class OSInfo:
    def __init__(self, hostname: str, domain: str, username: str, productname: str, editionid: str, releaseid: str, build: str, buildbranch: str, currentmajorversionnumber: str, currentversion: str, architecture: str, processorcount: str, isvirtualmachine: bool, boottimeutc: str, ishighintegrity: bool, islocaladmin: bool, currenttimeutc: str, timezone: str, timezoneutcoffset: str, locale: str, inputlanguage: str, installedinputlanguages: str, machineguid: str):
        self.Hostname = hostname
        self.Domain = domain
        self.Username = username
        self.ProductName = productname
        self.EditionId = editionid
        self.ReleaseId = releaseid
        self.Build = build
        self.BuildBranch = buildbranch
        self.CurrentMajorVersionNumber = currentmajorversionnumber
        self.CurrentVersion = currentversion
        self.Architecture = architecture
        self.ProcessorCount = processorcount
        self.IsVirtualMachine = isvirtualmachine
        self.BootTimeUtc = boottimeutc
        self.IsHighIntegrity = ishighintegrity
        self.IsLocalAdmin = islocaladmin
        self.CurrentTimeUtc = currenttimeutc
        self.TimeZone = timezone
        self.TimeZoneUtcOffset = timezoneutcoffset
        self.Locale = locale
        self.InputLanguage = inputlanguage
        self.InstalledInputLanguages = installedinputlanguages
        self.MachineGuid = machineguid


def is_vm(wmi_conn):
    searcher = wmi_conn.wmi_get('Select * from Win32_ComputerSystem')
    for s in searcher:
        data = wmi_conn.parse_wmi(s)
        manufacturer = data['Manufacturer'].lower()
        model = data['Model']
        if (manufacturer == 'microsoft corporation' and 'VIRTUAL' in model.upper()) or 'vmware' in manufacturer or 'xen' in manufacturer or model == 'VirtualBox':
            return True
        else:
            return False

def get_osinfo(wmi_conn, target):
    #TODO: Look into collecting other data from non remote if possible
    product_name = wmi_conn.get_string_value('HKLM', 'Software\\Microsoft\\Windows NT\\CurrentVersion', 'ProductName')
    edition_id = wmi_conn.get_string_value('HKLM', 'Software\\Microsoft\\Windows NT\\CurrentVersion', 'EditionID')
    release_id = wmi_conn.get_string_value('HKLM', 'Software\\Microsoft\\Windows NT\\CurrentVersion', 'ReleaseId')
    build_branch = wmi_conn.get_string_value('HKLM', 'Software\\Microsoft\\Windows NT\\CurrentVersion', 'BuildBranch')
    current_major_version = wmi_conn.get_dword_value('HKLM', 'Software\\Microsoft\\Windows NT\\CurrentVersion', 'CurrentMajorVersionNumber')
    current_version = wmi_conn.get_string_value('HKLM', 'Software\\Microsoft\\Windows NT\\CurrentVersion', 'CurrentVersion')

    build_number = wmi_conn.get_string_value('HKLM', 'Software\\Microsoft\\Windows NT\\CurrentVersion', 'CurrentBuildNumber')
    ubr = wmi_conn.get_string_value('HKLM', 'Software\\Microsoft\\Windows NT\\CurrentVersion', 'UBR')

    if ubr:
        build_number += f'.{ubr}'

    high_int = True
    local_admin = True

    arch = wmi_conn.get_env_var('PROCESSOR_ARCHITECTURE')
    proc_count = wmi_conn.get_env_var('NUMBER_OF_PROCESSORS')
    isvm = is_vm(wmi_conn)
    boot_time = datetime.min
    host_name = target
    domain = ''
    wd = wmi_conn.wmi_get('Select Domain from Win32_ComputerSystem')
    for w in wd:
        data = wmi_conn.parse_wmi(w)
        domain = data['Domain']
    machine_guid = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Microsoft\\Cryptography', 'MachineGuid')
    temp = []

    yield OSInfo(host_name, domain, '', product_name, edition_id, release_id, build_number, build_branch, str(current_major_version), current_version, arch, proc_count, isvm, boot_time, high_int, local_admin, datetime.now(timezone.utc), '', '', '', '', temp, machine_guid)

def format_results(info):
    print(f'  {'Hostname':<30}:  {info.Hostname}')
    print(f'  {'Domain Name':<30}:  {info.Domain}')
    print(f'  {'Username':<30}:  {info.Username}')
    print(f'  {'ProductName':<30}:  {info.ProductName}')
    print(f'  {'EditionID':<30}:  {info.EditionId}')
    print(f'  {'ReleaseID':<30}:  {info.ReleaseId}')
    print(f'  {'Build':<30}:  {info.Build}')
    print(f'  {'BuildBranch':<30}:  {info.BuildBranch}')
    print(f'  {'CurrentMajorVersionNumber':<30}:  {info.CurrentMajorVersionNumber}')
    print(f'  {'CurrentVersion':<30}:  {info.CurrentVersion}')
    print(f'  {'Architecture':<30}:  {info.Architecture}')
    print(f'  {'ProcessorCount':<30}:  {info.ProcessorCount}')
    print(f'  {'IsVirtualMachine':<30}:  {info.IsVirtualMachine}')

    if info.CurrentTimeUtc.tzinfo is None:
        current_time = info.CurrentTimeUtc.replace(tzinfo=timezone.utc)
    else:
        current_time = info.CurrentTimeUtc

    if info.BootTimeUtc.tzinfo is None:
        boot_time = info.BootTimeUtc.replace(tzinfo=timezone.utc)
    else:
        boot_time = info.BootTimeUtc
    uptime = current_time - boot_time
    boot_time_str = f"{uptime.days:02d}:{uptime.seconds//3600:02d}:{(uptime.seconds//60)%60:02d}:{uptime.seconds%60:02d}"
    boot_formatted = boot_time.strftime("%m/%d/%Y %I:%M:%S %p")
    current_utc_formatted = current_time.strftime("%m/%d/%Y %I:%M:%S %p")
    local_time_formatted = current_time.astimezone().strftime("%m/%d/%Y %I:%M:%S %p")
    
    print(f'  {"BootTimeUtc (approx)":<30}:  {boot_formatted} (Total uptime: {boot_time_str})')
    print(f'  {'HighIntegrity':<30}:  {info.IsHighIntegrity}')
    print(f'  {'IsLocalAdmin':<30}:  {info.IsLocalAdmin}')

    print(f'  {'CurrentTimeUtc':<30}:  {current_utc_formatted} (Local time: {local_time_formatted})')
    print(f'  {'TimeZone':<30}:  {info.TimeZone}')
    print(f'  {'TimeZoneOffset':<30}:  {info.TimeZoneUtcOffset}')
    print(f'  {'InputLanguage':<30}:  {info.InputLanguage}')
    print(f'  {'InstalledInputLanguages':<30}:  {info.InstalledInputLanguages}')
    print(f'  {'MachineGuid':<30}:  {info.MachineGuid}')

def command_base(options):
    command = 'OSInfo'
    description = 'Basic OS info (i.e. architecture, OS version, etc.)'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for info in get_osinfo(wmi_conn, address):
            if info is not None:
                format_results(info)
                print()
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()