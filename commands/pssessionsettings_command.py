
import re
import xml.etree.ElementTree as ET
from lib import MiscUtil
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class PSSessionSettings:
    def __init__(self, plugin: str, permission: list):
        self.Plugin = plugin
        self.Permission = permission

class PluginAccess:
    def __init__(self, principal: str, sid: str, permission: str):
        self.Principal = principal
        self.Sid = sid
        self.Permissions = permission

def parse_sddl(sddl_value: str):
    results = []
    ace_pattern = r'\((A|D|AU|OA|OD|AL);([^;]*);([^;]*);([^;]*);([^;]*);([^;(\r\n)]+)\)'
    matches = re.finditer(ace_pattern, sddl_value)
    
    well_known_sids = {
        # BUILTIN groups
        "BA": ("BUILTIN\\Administrators", "S-1-5-32-544"),
        "BU": ("BUILTIN\\Users", "S-1-5-32-545"),
        "BG": ("BUILTIN\\Guests", "S-1-5-32-546"),
        "BP": ("BUILTIN\\Power Users", "S-1-5-32-547"),
        "BO": ("BUILTIN\\Account Operators", "S-1-5-32-548"),
        "BS": ("BUILTIN\\Server Operators", "S-1-5-32-549"),
        "PU": ("BUILTIN\\Print Operators", "S-1-5-32-550"),
        "BK": ("BUILTIN\\Backup Operators", "S-1-5-32-551"),
        "RE": ("BUILTIN\\Replicator", "S-1-5-32-552"),
        "RC": ("BUILTIN\\Remote Desktop Users", "S-1-5-32-555"),
        "NO": ("BUILTIN\\Network Configuration Operators", "S-1-5-32-556"),
        "PA": ("BUILTIN\\Pre-Windows 2000 Compatible Access", "S-1-5-32-554"),
        "CN": ("BUILTIN\\Cryptographic Operators", "S-1-5-32-569"),
        "DD": ("BUILTIN\\Device Owners", "S-1-5-32-583"),
        "RU": ("BUILTIN\\Remote Management Users", "S-1-5-32-580"),
        
        # System and Well-Known SIDs
        "SY": ("NT AUTHORITY\\SYSTEM", "S-1-5-18"),
        "NS": ("NT AUTHORITY\\NETWORK SERVICE", "S-1-5-20"),
        "LS": ("NT AUTHORITY\\LOCAL SERVICE", "S-1-5-19"),
        "IU": ("NT AUTHORITY\\INTERACTIVE", "S-1-5-4"),
        "AN": ("NT AUTHORITY\\ANONYMOUS LOGON", "S-1-5-7"),
        "AU": ("NT AUTHORITY\\Authenticated Users", "S-1-5-11"),
        "AO": ("NT AUTHORITY\\Account Operators", "S-1-5-32-548"),
        "WD": ("Everyone", "S-1-1-0"),
        "CY": ("NT AUTHORITY\\SYSTEM", "S-1-5-18"),
        "OW": ("OWNER RIGHTS", "S-1-3-4"),
        "RM": ("NT AUTHORITY\\RESTRICTED", "S-1-5-12"),
        "WR": ("Everyone", "S-1-1-0"),
        "AC": ("ALL APPLICATION PACKAGES", "S-1-15-2-1"),
        "RA": ("RESTRICTED APPLICATION PACKAGES", "S-1-15-2-2"),
        "PS": ("Principal Self", "S-1-5-10"),
        "CO": ("Creator Owner", "S-1-3-0"),
        "CG": ("Creator Group", "S-1-3-1"),
        "NU": ("Network", "S-1-5-2"),
        "EA": ("Enterprise Admins", "S-1-5-21root domain-519"),
        "DA": ("Domain Admins", "S-1-5-21domain-512"),
        "DC": ("Domain Computers", "S-1-5-21domain-515"),
        "DU": ("Domain Users", "S-1-5-21domain-513"),
        "ED": ("Enterprise Domain Controllers", "S-1-5-9"),
        "CA": ("Certificate Publishers", "S-1-5-21domain-517"),
        "RS": ("RAS and IAS Servers", "S-1-5-21domain-553"),
    }

    ace_types = {
        "A": "AccessAllowed",
        "D": "AccessDenied",
        "OA": "ObjectAccessAllowed",
        "OD": "ObjectAccessDenied",
        "AU": "SystemAudit",
        "AL": "SystemAlarm"
    }
    
    for match in matches:
        ace_type, rights, inheritance_flags, prop_flags, object_type, trustee = match.groups()
        access_str = ace_types.get(ace_type, "Unknown")
        if trustee in well_known_sids:
            principal, sid = well_known_sids[trustee]
        elif trustee.startswith("S-1-"):
            principal = trustee
            sid = trustee
        else:
            if trustee.isalpha():
                principal = f"BUILTIN\\{trustee}"
                sid = trustee
            else:
                principal = trustee
                sid = trustee
            
        results.append((
            principal,
            sid,
            access_str
        ))
    
    return results

def get_ps_session_settings(wmi_conn):
    plugins = ["Microsoft.PowerShell", "Microsoft.PowerShell.Workflow", "Microsoft.PowerShell32"]

    for plugin in plugins:
        config = wmi_conn.get_string_value('HKLM', f'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Plugin\\{plugin}', 'ConfigXML')
        if config is None:
            continue
        access = []
        namespaces = {'pc': 'http://schemas.microsoft.com/wbem/wsman/1/config/PluginConfiguration'}
        
        root = ET.fromstring(config)
        security_element = root.find('.//pc:Security', namespaces)
        
        if security_element is not None:
            sddl = security_element.get('Sddl')
            if sddl:
                for principal, sid, access_str in parse_sddl(sddl):
                    access.append(PluginAccess(principal, sid, access_str))
    
        yield PSSessionSettings(plugin, access)

def format_results(settings):
    print(f'  Name : {settings.Plugin}')

    for access in settings.Permission:
        print(f'    {access.Principal:<35}    {access.Permissions:<22}')
    print()

def command_base(options):
    command = 'PSSessionSettings'
    description = 'Enumerates PS Session Settings from the registry'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"
    
    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for settings in get_ps_session_settings(wmi_conn):
            if settings is not None:
                format_results(settings)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()