
import base64
from textwrap import wrap
from enum import IntEnum
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class SysmonHashAlgorithm(IntEnum):
    NotDefined = 0
    SHA1 = 1
    MD5 = 2
    SHA256 = 4
    IMPHASH = 8

class SysmonOptions(IntEnum):
    NotDefined = 0
    NetworkConnection = 1
    ImageLoading = 2

class Sysmon:
    def __init__(self, installed: bool, hashingalgorithm: SysmonHashAlgorithm, options: SysmonOptions, rules: str):
        self.Installed = installed
        self.HashingAlgorithm = hashingalgorithm
        self.Options = options
        self.Rules = rules

def format_string(string, length):
    return [string[i:i+length] for i in range(0, len(string), length)]

def get_sysmon_alg(value):
    algorithms = []
    for alg in SysmonHashAlgorithm:
        if value & alg.value:
            algorithms.append(alg.name)
    return ', '.join(algorithms)

def get_sysmon(wmi_conn):
    reg_hash_alg = wmi_conn.get_dword_value('HKLM', 'SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters', 'HashingAlgorithm')
    reg_options = wmi_conn.get_dword_value('HKLM', 'SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters', 'Options')
    reg_sysmon_rules = wmi_conn.get_binary_value('HKLM', 'SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters', 'Rules')

    installed = False
    hashing_alg = SysmonHashAlgorithm(0)
    sysmon_options = SysmonOptions(0)
    base64_rules = None

    if reg_hash_alg is not None or reg_options is not None or reg_sysmon_rules is not None:
        installed = True
    if reg_hash_alg is not None and reg_hash_alg != 0:
        reg_hash_alg = reg_hash_alg & 15
        #hashing_alg = SysmonHashAlgorithm(int(reg_hash_alg)).name
        hashing_alg = get_sysmon_alg(int(reg_hash_alg))
    if reg_options is not None:
        try:
            sysmon_options = SysmonOptions(reg_options).name
        except:
            sysmon_options = reg_options
    if reg_sysmon_rules is not None:
        base64_rules = base64.b64encode(reg_sysmon_rules).decode('utf-8')

    yield Sysmon(installed, hashing_alg, sysmon_options, base64_rules)

def format_results(sysmon):
    print(f'Installed:        {sysmon.Installed}')
    print(f'HashingAlgorithm: {sysmon.HashingAlgorithm}')
    print(f'Options:          {sysmon.Options}')
    print('Rules:')

    for line in format_string(sysmon.Rules, 100):
        print(f'    {line}')

def command_base(options):
    command = 'Sysmon'
    description = 'Sysmon configuration from the registry'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"
    
    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for sysmon in get_sysmon(wmi_conn):
            if sysmon is not None:
                PrintHandler.print_props(sysmon)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()