

from enum import IntEnum
from lib import PrintHandler
from lib import WMIHandler
from impacket.examples.utils import parse_target

class FirewallAction(IntEnum):
    ALLOW = 0
    BLOCK = 1

class WindowsFirewallProfileSettings:
    def __init__(self, present: bool = False, enabled: bool = False, defaultinboundaction: FirewallAction = None, defaultoutboundaction: FirewallAction = None, disablenotifications: bool = None):
        self.Present = present
        self.Enabled = enabled
        self.DefaultInboundAction = defaultinboundaction
        self.DefaultOutboundAction = defaultoutboundaction
        self.DisableNotifications = disablenotifications

class WindowsFirewallRule:
    def __init__(self, name: str = None, description: str = None, applicationname: str = None, protocol: str = None, action: str = None, direction: str = None, profiles: str = None, localaddress: str = None, localports: str = None, remoteaddress: str = None, remoteports: str = None):
        self.Name = name
        self.Description = description
        self.ApplicationName = applicationname
        self.Protocol = protocol
        self.Action = action
        self.Direction = direction
        self.Profiles = profiles
        self.LocalAddresses = localaddress
        self.LocalPorts = localports
        self.RemoteAddresses = remoteaddress
        self.RemotePorts = remoteports

class WindowsFirewall:
    def __init__(self, location: str):
        self.Location = location
        self.Domain = WindowsFirewallProfileSettings()
        self.Private = WindowsFirewallProfileSettings()
        self.Public = WindowsFirewallProfileSettings()
        self.Standard = WindowsFirewallProfileSettings()
        self.Rules = []

def get_fw_rules(wmi_conn, args):
    direction_args = []
    protocol_args = []
    action_args = []
    profile_args = []
    filter_results = True

    if len(args) > 0:
        filter_results = False
        print('Collecting all Windows Firewall Rules\n\n')
        for arg in args:
            if arg.lower() == 'allow':
                action_args.append('Allow')
            elif arg.lower() == 'deny' or arg.lower() == 'block':
                action_args.append('Block')
            elif arg.lower() == 'tcp':
                protocol_args.append('TCP')
            elif arg.lower() == 'udp':
                protocol_args.append('UDP')
            elif arg.lower() == 'in':
                direction_args.append('In')
            elif arg.lower() == 'out':
                direction_args.append('Out')
            elif arg.lower() == 'domain':
                profile_args.append('Domain')
            elif arg.lower() == 'private':
                profile_args.append('Private')
            elif arg.lower() == 'public':
                profile_args.append('Public')
    else:
        print('Collecting Windows Firewall Non-standard Rules\n\n')

    protocols = {
        "0": "HOPOPT",
        "1": "ICMP",
        "2": "IGMP",
        "3": "GGP",
        "4": "IPv4",
        "5": "ST",
        "6": "TCP",
        "7": "CBT",
        "8": "EGP",
        "9": "IGP",
        "10": "BBN-RCC-MON",
        "11": "NVP-II",
        "12": "PUP",
        "13": "ARGUS",
        "14": "EMCON",
        "15": "XNET",
        "16": "CHAOS",
        "17": "UDP",
        "18": "MUX",
        "19": "DCN-MEAS",
        "20": "HMP",
        "21": "PRM",
        "22": "XNS-IDP",
        "23": "TRUNK-1",
        "24": "TRUNK-2",
        "25": "LEAF-1",
        "26": "LEAF-2",
        "27": "RDP",
        "28": "IRTP",
        "29": "ISO-TP4",
        "30": "NETBLT",
        "31": "MFE-NSP",
        "32": "MERIT-INP",
        "33": "DCCP",
        "34": "3PC",
        "35": "IDPR",
        "36": "XTP",
        "37": "DDP",
        "38": "IDPR-CMTP",
        "39": "TP++",
        "40": "IL",
        "41": "IPv6",
        "42": "SDRP",
        "43": "IPv6-Route",
        "44": "IPv6-Frag",
        "45": "IDRP",
        "46": "RSVP",
        "47": "GRE",
        "48": "DSR",
        "49": "BNA",
        "50": "ESP",
        "51": "AH",
        "52": "I-NLSP",
        "53": "SWIPE",
        "54": "NARP",
        "55": "MOBILE",
        "56": "TLSP",
        "57": "SKIP",
        "58": "IPv6-ICMP",
        "59": "IPv6-NoNxt",
        "60": "IPv6-Opts",
        "61": "any host",
        "62": "CFTP",
        "63": "any local",
        "64": "SAT-EXPAK",
        "65": "KRYPTOLAN",
        "66": "RVD",
        "67": "IPPC",
        "68": "any distributed file system",
        "69": "SAT-MON",
        "70": "VISA",
        "71": "IPCV",
        "72": "CPNX",
        "73": "CPHB",
        "74": "WSN",
        "75": "PVP",
        "76": "BR-SAT-MON",
        "77": "SUN-ND",
        "78": "WB-MON",
        "79": "WB-EXPAK",
        "80": "ISO-IP",
        "81": "VMTP",
        "82": "SECURE-VMTP",
        "83": "VINES",
        "84": "TTP",
        "85": "NSFNET-IGP",
        "86": "DGP",
        "87": "TCF",
        "88": "EIGRP",
        "89": "OSPFIGP",
        "90": "Sprite-RPC",
        "91": "LARP",
        "92": "MTP",
        "93": "AX.25",
        "94": "IPIP",
        "95": "MICP",
        "96": "SCC-SP",
        "97": "ETHERIP",
        "98": "ENCAP",
        "99": "any private encryption scheme",
        "100": "GMTP",
        "101": "IFMP",
        "102": "PNNI",
        "103": "PIM",
        "104": "ARIS",
        "105": "SCPS",
        "106": "QNX",
        "107": "A/N",
        "108": "IPComp",
        "109": "SNP",
        "110": "Compaq-Peer",
        "111": "IPX-in-IP",
        "112": "VRRP",
        "113": "PGM",
        "114": "0-hop",
        "115": "L2TP",
        "116": "DDX",
        "117": "IATP",
        "118": "STP",
        "119": "SRP",
        "120": "UTI",
        "121": "SMP",
        "122": "SM",
        "123": "PTP",
        "124": "ISIS",
        "125": "FIRE",
        "126": "CRTP",
        "127": "CRUDP",
        "128": "SSCOPMCE",
        "129": "IPLT",
        "130": "SPS",
        "131": "PIPE",
        "132": "SCTP",
        "133": "FC",
        "134": "RSVP-E2E-IGNORE",
        "135": "Mobility",
        "136": "UDPLite",
        "137": "MPLS-in-IP",
        "138": "manet",
        "139": "HIP",
        "140": "Shim6",
        "141": "WESP",
        "142": "ROHC",
        "143": "Unassigned",
        "253": "Experimentation",
        "254": "Experimentation",
        "255": "Reserved"
    }

    rule_locations = [
        'SOFTWARE\\Policies\\Microsoft\\WindowsFirewall',
        'SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy'
    ]
    for rule_location in rule_locations:
        firewall_rules = wmi_conn.get_registry_value('HKLM', f'{rule_location}\\FirewallRules')
        if firewall_rules is not None:
            output = WindowsFirewall(rule_location)
            
            domain_profile_enabled = wmi_conn.get_dword_value('HKLM', f'{rule_location}\\DomainProfile', 'EnableFirewall')
            if domain_profile_enabled is not None:
                output.Domain.Present = True

                domain_profile_inbound = wmi_conn.get_dword_value('HKLM', f'{rule_location}\\DomainProfile', 'DefaultInboundAction')
                domain_profile_outbound = wmi_conn.get_dword_value('HKLM', f'{rule_location}\\DomainProfile', 'DefaultOutboundAction')
                domain_profile_notifications = wmi_conn.get_dword_value('HKLM', f'{rule_location}\\DomainProfile', 'DisableNotifications')

                output.Domain.Enabled = domain_profile_enabled == 1
                if domain_profile_enabled is not None:
                    if domain_profile_notifications is not None:
                        output.Domain.DisableNotifications = domain_profile_notifications == 1
                    if domain_profile_inbound is not None:
                        output.Domain.DefaultInboundAction = FirewallAction(domain_profile_inbound).name
                    if domain_profile_outbound is not None:
                        output.Domain.DefaultOutboundAction = FirewallAction(domain_profile_outbound).name

            public_profile_enabled = wmi_conn.get_dword_value('HKLM', f'{rule_location}\\PublicProfile', 'EnableFirewall')
            if public_profile_enabled is not None:
                output.Public.Present = True

                public_profile_inbound = wmi_conn.get_dword_value('HKLM', f'{rule_location}\\PublicProfile', 'DefaultInboundAction')
                public_profile_outbound = wmi_conn.get_dword_value('HKLM', f'{rule_location}\\PublicProfile', 'DefaultOutboundAction')
                public_profile_notifications = wmi_conn.get_dword_value('HKLM', f'{rule_location}\\PublicProfile', 'DisableNotifications')

                output.Public.Enabled = public_profile_enabled == 1
                if public_profile_enabled is not None:
                    if public_profile_notifications is not None:
                        output.Public.DisableNotifications = public_profile_notifications == 1
                    if public_profile_inbound is not None:
                        output.Public.DefaultInboundAction = FirewallAction(public_profile_inbound).name
                    if public_profile_outbound is not None:
                        output.Public.DefaultOutboundAction = FirewallAction(public_profile_outbound).name

            private_profile_enabled = wmi_conn.get_dword_value('HKLM', f'{rule_location}\\PrivateProfile', 'EnableFirewall')
            if private_profile_enabled is not None:
                output.Private.Present = True

                private_profile_inbound = wmi_conn.get_dword_value('HKLM', f'{rule_location}\\PrivateProfile', 'DefaultInboundAction')
                private_profile_outbound = wmi_conn.get_dword_value('HKLM', f'{rule_location}\\PrivateProfile', 'DefaultOutboundAction')
                private_profile_notifications = wmi_conn.get_dword_value('HKLM', f'{rule_location}\\PrivateProfile', 'DisableNotifications')

                output.Private.Enabled = private_profile_enabled == 1
                if private_profile_enabled is not None:
                    if private_profile_notifications is not None:
                        output.Private.DisableNotifications = private_profile_notifications == 1
                    if private_profile_inbound is not None:
                        output.Private.DefaultInboundAction = FirewallAction(private_profile_inbound).name
                    if private_profile_outbound is not None:
                        output.Private.DefaultOutboundAction = FirewallAction(private_profile_outbound).name

            standard_profile_enabled = wmi_conn.get_dword_value('HKLM', f'{rule_location}\\StandardProfile', 'EnableFirewall')
            if standard_profile_enabled is not None:
                output.Standard.Present = True

                standard_profile_inbound = wmi_conn.get_dword_value('HKLM', f'{rule_location}\\StandardProfile', 'DefaultInboundAction')
                standard_profile_outbound = wmi_conn.get_dword_value('HKLM', f'{rule_location}\\StandardProfile', 'DefaultOutboundAction')
                standard_profile_notifications = wmi_conn.get_dword_value('HKLM', f'{rule_location}\\StandardProfile', 'DisableNotifications')

                output.Standard.Enabled = standard_profile_enabled == 1
                if standard_profile_enabled is not None:
                    if standard_profile_notifications is not None:
                        output.Standard.DisableNotifications = standard_profile_notifications == 1
                    if standard_profile_inbound is not None:
                        output.Standard.DefaultInboundAction = FirewallAction(standard_profile_inbound).name
                    if standard_profile_outbound is not None:
                        output.Standard.DefaultOutboundAction = FirewallAction(standard_profile_outbound).name

            for key, value in firewall_rules.items():
                rule = WindowsFirewallRule()
                props = value.split('|')
                for prop in props:
                    onv = prop.split('=')
                    if len(onv) == 1:
                        continue
                    k = onv[0]
                    v = onv[1]

                    if k == 'Action':
                        rule.Action = v
                    elif k == 'Active':
                        pass
                    elif k == 'Dir':
                        rule.Direction = v
                    elif k == 'Protocol':
                        rule.Protocol = protocols[v]
                    elif k == 'Name':
                        rule.Name = v
                    elif k == 'Desc':
                        rule.Description = v
                    elif k == 'App':
                        rule.ApplicationName = v
                    elif k == 'Profile':
                        rule.Profiles = v
                    elif k == 'RPort':
                        rule.RemotePorts = v
                    elif k == 'LPort':
                        rule.LocalPorts = v
                    elif k == 'RA4':
                        rule.RemoteAddresses = v
                    elif k == 'LA4':
                        rule.LocalAddresses = v

                if not filter_results or (len(action_args) == 0 and len(protocol_args) == 0 and len(direction_args) == 0 and len(profile_args) == 0 and 
                    not rule.Name.startswith("@") and 
                    not rule.Name == "Shell Input Application" and rule.Action == "Block"
                    ) or (
                    ("Allow" in action_args and rule.Action == "Allow") or
                    ("Block" in action_args and rule.Action == "Block") or
                    ("TCP" in protocol_args and rule.Protocol == "TCP") or
                    ("UDP" in protocol_args and rule.Protocol == "UDP") or
                    ("In" in direction_args and rule.Direction == "In") or
                    ("Out" in direction_args and rule.Direction == "Out") or
                    ("Domain" in profile_args and rule.Profiles.strip() == "Domain") or
                    ("Private" in profile_args and rule.Profiles.strip() == "Private") or
                    ("Public" in profile_args and rule.Profiles.strip() == "Public")):
                    output.Rules.append(rule)
                    
        yield output

def format_results(firewall):
    print(f'Location                     : {firewall.Location}\n')

    if firewall.Domain.Present:
        print('Domain Profile')
        print(f'    Enabled                  : {firewall.Domain.Enabled}')
        print(f'    DisableNotifications     : {firewall.Domain.DisableNotifications}')
        print(f'    DefaultInboundAction     : {firewall.Domain.DefaultInboundAction}')
        print(f'    DefaultOutboundAction    : {firewall.Domain.DefaultOutboundAction}\n')

    if firewall.Private.Present:
        print('Private Profile')
        print(f'    Enabled                  : {firewall.Private.Enabled}')
        print(f'    DisableNotifications     : {firewall.Private.DisableNotifications}')
        print(f'    DefaultInboundAction     : {firewall.Private.DefaultInboundAction}')
        print(f'    DefaultOutboundAction    : {firewall.Private.DefaultOutboundAction}\n')

    if firewall.Public.Present:
        print('Public Profile')
        print(f'    Enabled                  : {firewall.Public.Enabled}')
        print(f'    DisableNotifications     : {firewall.Public.DisableNotifications}')
        print(f'    DefaultInboundAction     : {firewall.Public.DefaultInboundAction}')
        print(f'    DefaultOutboundAction    : {firewall.Public.DefaultOutboundAction}\n')

    if firewall.Standard.Present:
        print('Standard Profile')
        print(f'    Enabled                  : {firewall.Standard.Enabled}')
        print(f'    DisableNotifications     : {firewall.Standard.DisableNotifications}')
        print(f'    DefaultInboundAction     : {firewall.Standard.DefaultInboundAction}')
        print(f'    DefaultOutboundAction    : {firewall.Standard.DefaultOutboundAction}\n')

    if len(firewall.Rules) > 0:
        print('Rules:\n')
        for rule in firewall.Rules:
            print(f"  Name                 : {rule.Name}")
            print(f"  Description          : {rule.Description}")
            print(f"  ApplicationName      : {rule.ApplicationName}")
            print(f"  Protocol             : {rule.Protocol}")
            print(f"  Action               : {rule.Action}")
            print(f"  Direction            : {rule.Direction}")
            print(f"  Profiles             : {rule.Profiles}")
            print(f"  Local Addr:Port      : {rule.LocalAddresses}:{rule.LocalPorts}")
            print(f"  Remote Addr:Port     : {rule.RemoteAddresses}:{rule.RemotePorts}\n")

def command_base(options):
    command = 'WindowsFirewall'
    description = 'Non-standard firewall rules, "-full" dumps all (arguments == allow/deny/tcp/udp/in/out/domain/private/public)'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"
    
    args = ''
    try:
        module_args = options.command_args[command.lower()]
        if module_args:
            args = module_args.split()
    except:
        pass

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for fw in get_fw_rules(wmi_conn, args):
            if fw is not None:
                format_results(fw)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()
    