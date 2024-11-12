
import re
import xml.etree.ElementTree as ET
from enum import IntEnum
from datetime import datetime, timedelta, timezone
from lib import EVENHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class SECURITY_LOGON_TYPE(IntEnum):
    Interactive = 2               # logging on interactively.
    Network = 3                   # logging using a network.
    Batch = 4                     # logon for a batch process.
    Service = 5                   # logon for a service account.
    Proxy = 6                     # Not supported.
    Unlock = 7                    # Tattempt to unlock a workstation.
    NetworkCleartext = 8          # network logon with cleartext credentials
    NewCredentials = 9            # caller can clone its current token and specify new credentials for outbound connections
    RemoteInteractive = 10        # terminal server session that is both remote and interactive
    CachedInteractive = 11        # attempt to use the cached credentials without going out across the network
    CachedRemoteInteractive = 12  # same as RemoteInteractive, except used internally for auditing purposes
    CachedUnlock = 13             # attempt to unlock a workstation

class LogonEvents:
    def __init__(self, timecreatedutc: datetime, targetusername :str, targetdomainname: str, logontype: str, ipaddress: str, subjectusername: str, subjectdomainname: str, authenticationpackage: str, lmpackage: str, targetoutboundusername: str, targetoutbounddomainname: str):
        self.TimeCreatedUtc = timecreatedutc
        self.TargetUserName = targetusername
        self.TargetDomainName = targetdomainname
        self.LogonType = logontype
        self.IpAddress = ipaddress
        self.SubjectUserName = subjectusername
        self.SubjectDomainName = subjectdomainname
        self.AuthenticationPackage = authenticationpackage
        self.LmPackage = lmpackage
        self.TargetOutboundUserName = targetoutboundusername
        self.TargetOutboundDomainName = targetoutbounddomainname

def print_user_set(users):
    sorted_users = sorted(users)
    line = ""
    
    for i in range(len(sorted_users)):
        if i % 3 == 0:
            if line:
                print(line)
            line = "    "
        line += f"{sorted_users[i]:<30}"
    if line:
        print(line)
    print()

def get_logon_events(even_conn, args):
    ntlm_v1_users = set()
    ntlm_v2_users = set()
    kerberos_users = set()
    user_regex = None
    last_days = 10
    if len(args) >= 1:
        try:
            last_days = int(args[0])
        except (TypeError, ValueError):
            print('ERROR: Argument is not an integer')
            return

    if len(args) >=2:
        user_regex = args[1]
        print(f'Username Filter: {user_regex}')

    log_name = 'Security'
    eid = '4624'
    
    start_time = datetime.now() - timedelta(days=last_days)
    end_time = datetime.now()
    start_time_utc = start_time.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    end_time_utc = end_time.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    query = f"*[System/EventID={eid}] and *[System[TimeCreated[@SystemTime >= '{start_time_utc}']]] and *[System[TimeCreated[@SystemTime <= '{end_time_utc}']]]"

    print(f'Listing 4624 Account Logon Events for the last {last_days} days.\n')
    print("  TimeCreated,TargetUser,LogonType,IpAddress,SubjectUsername,AuthenticationPackageName,LmPackageName,TargetOutboundUser")

    xml_event = even_conn.EvtRpcRegisterLogQuery_EvtRpcQueryNext(log_name, query)
    for event in xml_event:
        data = even_conn.parse_xml(event)
        subject_username = data['SubjectUserName']
        subject_domainname = data['SubjectDomainName']
        target_username = data['TargetUserName']
        target_domainname = data['TargetDomainName']
        logon_type = SECURITY_LOGON_TYPE(int(data['LogonType'])).name
        authentication_package = data['AuthenticationPackageName']
        lm_package = data['LmPackageName']
        lm_package_name = "" if lm_package == "-" else lm_package
        ip_address = data['IpAddress']

        target_outbound_user = '-'
        target_outbound_domain = '-'
        if 'TargetOutboundUserName' in data:
            target_outbound_user = data['TargetOutboundUserName']
        if 'TargetOutboundDomainName' in data:
            target_outbound_domain = data['TargetOutboundDomainName']

        user_ignore_regex = f"^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|UMFD-[0-9]+|DWM-[0-9]+|ANONYMOUS LOGON|{data['Computer']}\\$)$"
        domain_ignore_regex = "^(NT VIRTUAL MACHINE)$"

        if user_regex is None and re.match(user_ignore_regex, target_username, re.IGNORECASE):
            continue

        if user_regex is None and re.match(domain_ignore_regex, target_domainname, re.IGNORECASE):
            continue

        if user_regex is not None and not re.match(user_regex, target_username, re.IGNORECASE):
            continue

        if logon_type == 'Network':
            account_name = f'{target_domainname}\\{target_username}'
            if authentication_package == 'NTLM':
                if lm_package_name == 'NTLM V1':
                    ntlm_v1_users.add(account_name)
                elif lm_package_name == 'NTLM V2':
                    ntlm_v2_users.add(account_name)
            elif authentication_package == 'Kerberos':
                kerberos_users.add(account_name)

        yield LogonEvents(data['TimeCreated.SystemTime'], target_username, target_domainname, logon_type, ip_address, subject_username, subject_domainname, authentication_package, lm_package, target_outbound_user, target_outbound_domain)

        #Prints a little bit differently than seatbelt, move to format_results
        if len(ntlm_v1_users) > 0 or len(ntlm_v2_users) > 0:
            print('\n  Other accounts authenticate to this machine using NTLM! NTLM-relay may be possible')
        
        if len(ntlm_v1_users) > 0:
            print("\n  Accounts authenticate to this machine using NTLM v1!")
            print("  You can obtain these accounts' **NTLM** hashes by sniffing NTLM challenge/responses and then cracking them!")
            print("  NTLM v1 authentication is 100 percent broken!\n")

            print_user_set(ntlm_v1_users)
        
        if len(ntlm_v2_users) > 0:
            print("\n  Accounts authenticate to this machine using NTLM v2!")
            print("  You can obtain NetNTLMv2 for these accounts by sniffing NTLM challenge/responses.")
            print("  You can then try and crack their passwords.\n")

            print_user_set(ntlm_v2_users)

        if len(kerberos_users) > 0:
            print('\n  The following users have authenticated to this machine using Kerberos.\n')

            print_user_set(kerberos_users)
    
def format_results(logon):
    target_user = f'{logon.TargetDomainName}\\{logon.TargetUserName}'
    subject_user = f'{logon.SubjectDomainName}\\{logon.SubjectUserName}'
    utc_dt = datetime.fromisoformat(logon.TimeCreatedUtc).replace(tzinfo=timezone.utc)
    formatted_time = utc_dt.astimezone().strftime("%m/%d/%Y %I:%M %p")
    target_outbound_user = ''
    if logon.TargetOutboundUserName != '-':
        target_outbound_user = f'{logon.TargetOutboundDomainName}\\{logon.TargetOutboundUserName}'
    print(f'  {formatted_time},{target_user},{logon.LogonType},{logon.IpAddress},{subject_user},{logon.AuthenticationPackage},{logon.LmPackage},{target_outbound_user}')

def command_base(options):
    command = 'LogonEvents'
    description = 'Logon events (Event ID 4624) from the security event log. Default of 10 days, argument == last X days.'
    command_group = ['misc', 'remote']
    
    args = ''
    if options.command_args:
        module_args = options.command_args[command.lower()]
        if module_args:
            args = module_args.split()

    domain, username, password, address = parse_target(options.target)
    
    PrintHandler.show_banner(command)
    try:
        even_conn = EVENHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        even_conn.connect()
        for events in get_logon_events(even_conn, args):
            if events is not None:
                format_results(events)
    except KeyboardInterrupt:
        even_conn.close()
    except Exception as e:
        print(e)

    even_conn.close()