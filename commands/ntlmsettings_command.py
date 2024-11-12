
from enum import IntEnum
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class SessionSecurity(IntEnum):
    none = 0x00000000
    Integrity = 0x00000010
    Confidentiality = 0x00000020
    NTLMv2 = 0x00080000
    Require128BitKey = 0x20000000
    Require56BitKey = 0x80000000

class NTLMSettings:
    def __init__(self, lanmancompatabilitylevel: str, clientrequiresigning: bool, clientnegotiatesigning: bool, serverrequiresigning: bool, servernegotiatesigning: bool, ldapsigning: str, ntlmminclientsec: str, ntlmminserversec: str, inboundrestrictions: str, outboundrestrictions: str, inboundauditing: str, outboundexceptions: str):
        self.LanmanCompatabilityLevel = lanmancompatabilitylevel
        self.ClientRequireSigning = clientrequiresigning
        self.ClientNegotiateSigning = clientnegotiatesigning
        self.ServerRequireSigning = serverrequiresigning
        self.ServerNegotiateSigning = servernegotiatesigning
        self.LdapSigning = ldapsigning
        self.NTLMMinClientSec = ntlmminclientsec
        self.NTLMMinServerSec = ntlmminserversec
        self.InboundRestrictions = inboundrestrictions
        self.OutboundRestrictions = outboundrestrictions
        self.InboundAuditing = inboundauditing
        self.OutboundExceptions = outboundexceptions

def get_ntlm_settings(wmi_conn):
    lanman_compat_level = wmi_conn.get_dword_value('HKLM', 'System\\CurrentControlSet\\Control\\Lsa', 'LmCompatibilityLevel')
    client_req_signing = wmi_conn.get_dword_value('HKLM', 'System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters', 'RequireSecuritySignature') == 1
    client_nego_signing = wmi_conn.get_dword_value('HKLM', 'System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters', 'EnableSecuritySignature') == 1
    server_req_signing = wmi_conn.get_dword_value('HKLM', 'System\\CurrentControlSet\\Services\\LanmanServer\\Parameters', 'RequireSecuritySignature') == 1
    server_nego_siging = wmi_conn.get_dword_value('HKLM', 'System\\CurrentControlSet\\Services\\LanmanServer\\Parameters', 'EnableSecuritySignature') == 1

    ldap_signing = wmi_conn.get_dword_value('HKLM', 'System\\CurrentControlSet\\Services\\LDAP', 'LDAPClientIntegrity')

    ntlm_min_client_sec = wmi_conn.get_dword_value('HKLM', 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0', 'NtlmMinClientSec')
    ntlm_min_server_sec = wmi_conn.get_dword_value('HKLM', 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0', 'NtlmMinServerSec')
    inbound_restrict = wmi_conn.get_dword_value('HKLM', 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0', 'RestrictReceivingNTLMTraffic')
    outbound_restrict = wmi_conn.get_dword_value('HKLM', 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0', 'RestrictSendingNTLMTraffic')
    inbound_audit = wmi_conn.get_dword_value('HKLM', 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0', 'AuditReceivingNTLMTraffic')
    outbound_except = wmi_conn.get_string_value('HKLM', 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0', 'ClientAllowedNTLMServers')
    yield NTLMSettings(lanman_compat_level, client_req_signing, client_nego_signing, server_req_signing, server_nego_siging, ldap_signing, ntlm_min_client_sec, ntlm_min_server_sec, inbound_restrict, outbound_restrict, inbound_audit, outbound_except)

def format_results(ntlm):
    
    lmstr = None
    if ntlm.LanmanCompatabilityLevel == 'Send LM & NTLM responses':
        lmstr = 'Send LM & NTLM responses'
    elif ntlm.LanmanCompatabilityLevel == 'Send LM & NTLM - Use NTLMv2 session security if negotiated':
        lmstr = 'Send LM & NTLM - Use NTLMv2 session security if negotiated'
    elif ntlm.LanmanCompatabilityLevel == 'Send NTLM response only':
        lmstr = 'Send NTLM response only'
    elif ntlm.LanmanCompatabilityLevel == None:
        #lmstr = None
        lmstr = 'Send NTLMv2 response only - Win7+ default'
    elif ntlm.LanmanCompatabilityLevel == 'Send NTLMv2 response only - Win7+ default':
        lmstr = 'Send NTLMv2 response only - Win7+ default'
    elif ntlm.LanmanCompatabilityLevel == 'Send NTLMv2 response only. DC: Refuse LM':
        lmstr = 'Send NTLMv2 response only. DC: Refuse LM'
    elif ntlm.LanmanCompatabilityLevel == 'Send NTLMv2 response only. DC: Refuse LM & NTLM':
        lmstr = 'Send NTLMv2 response only. DC: Refuse LM & NTLM'
    elif ntlm.LanmanCompatabilityLevel == 'Unknown':
        lmstr = 'Unknown'
    print(f"  LanmanCompatibilityLevel    : {ntlm.LanmanCompatabilityLevel}({lmstr})")

    print("\n  NTLM Signing Settings")
    print(f"      ClientRequireSigning    : {ntlm.ClientRequireSigning}")
    print(f"      ClientNegotiateSigning  : {ntlm.ClientNegotiateSigning}")
    print(f"      ServerRequireSigning    : {ntlm.ServerRequireSigning}")
    print(f"      ServerNegotiateSigning  : {ntlm.ServerNegotiateSigning}")

    ldap_signing_str = None

    if ntlm.LdapSigning == 0:
        ldap_signing_str = 'No signing'
    elif ntlm.LdapSigning == 1:
        ldap_signing_str = 'Negotiate signing'
    elif ntlm.LdapSigning == 2:
        ldap_signing_str = 'Require Signing'
    else:
        ldap_signing_str = 'Unknown'
    print(f"      LdapSigning             : {ntlm.LdapSigning} ({ldap_signing_str})")
    print("\n  Session Security")

    if ntlm.NTLMMinClientSec is not None:
        client_sess_sec = SessionSecurity(int(ntlm.NTLMMinClientSec)).name
        print(f"      NTLMMinClientSec        : {ntlm.NTLMMinClientSec} ({client_sess_sec})")

        if ntlm.LanmanCompatabilityLevel is not None and int(ntlm.LanmanCompatabilityLevel) < 3 and not (client_sess_sec & SessionSecurity.NTLMv2):
            print("        [!] NTLM clients support NTLMv1!")

    if ntlm.NTLMMinServerSec is not None:
        server_sess_sec = SessionSecurity(int(ntlm.NTLMMinServerSec)).name
        print(f"      NTLMMinServerSec        : {ntlm.NTLMMinServerSec} ({server_sess_sec})\n")

        if ntlm.LanmanCompatabilityLevel is not None and int(ntlm.LanmanCompatabilityLevel) < 3 and not (server_sess_sec & SessionSecurity.NTLMv2):
            print("        [!] NTLM services on this machine support NTLMv1!")

    inbound_rest_str = None
    if ntlm.InboundRestrictions == 0:
        inbound_rest_str = 'Allow all'
    elif ntlm.InboundRestrictions == 1:
        inbound_rest_str = 'Deny all domain accounts'
    elif ntlm.InboundRestrictions == 2:
        inbound_rest_str = 'Deny all accounts'
    else:
        inbound_rest_str = 'Not defined'

    oubound_rest_str = None
    if ntlm.OutboundRestrictions == 0:
        oubound_rest_str = 'Allow All'
    elif ntlm.OutboundRestrictions == 1:
        oubound_rest_str = 'Audit All'
    elif ntlm.OutboundRestrictions == 2:
        oubound_rest_str = 'Deny All'
    else:
        oubound_rest_str = 'Not defined'

    inbound_audit_str = None
    if ntlm.InboundAuditing == 0:
        inbound_audit_str = 'Disable'
    elif ntlm.InboundAuditing == 1:
        inbound_audit_str = 'Enable auditing for domain accounts'
    elif ntlm.InboundAuditing == 2:
        inbound_audit_str = 'Enable auditing for all accounts'
    else:
        inbound_audit_str = 'Not defined'

    print("\n  NTLM Auditing and Restrictions")
    print(f"      InboundRestrictions     : {ntlm.InboundRestrictions}({inbound_rest_str})")
    print(f"      OutboundRestrictions    : {ntlm.OutboundRestrictions}({oubound_rest_str})")
    print(f"      InboundAuditing         : {ntlm.InboundAuditing}({inbound_audit_str})")
    print(f"      OutboundExceptions      : {ntlm.OutboundExceptions}")

def command_base(options):
    command = 'NTLMSettings'
    description = 'NTLM authentication settings'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for settings in get_ntlm_settings(wmi_conn):
            if settings is not None:
                format_results(settings)
                #print()
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()