
import re
from datetime import datetime, timedelta, timezone
from lib import EVENHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class ExplicitLogonEvents:
    def __init__(self, subjectuser: str, subjectdomain :str, targetuser: str, targetdomain: str, process: str, ipaddress: str, timecreatedutc: datetime):
        self.SubjectUser = subjectuser
        self.SubjectDomain = subjectdomain
        self.TargetUser = targetuser
        self.TargetDomain = targetdomain
        self.Process = process
        self.IpAddress = ipaddress
        self.TimeCreatedUtc = timecreatedutc

def get_explicit_logon_events(even_conn, args):
    user_regex = None
    filter_results = False
    last_days = 7

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
    eid = '4648'
    start_time = datetime.now() - timedelta(days=last_days)
    end_time = datetime.now()
    start_time_utc = start_time.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    end_time_utc = end_time.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    query = f"*[System/EventID={eid}] and *[System[TimeCreated[@SystemTime >= '{start_time_utc}']]] and *[System[TimeCreated[@SystemTime <= '{end_time_utc}']]]"

    print(f'Listing 4648 Explicit Credential Events - A process logged on using plaintext credentials over last {last_days} days')
    print("Output Format:")
    print("  --- TargetUser,ProcessResults,SubjectUser,IpAddress ---")
    print("  <Dates the credential was used to logon>\n\n")
    xml_event = even_conn.EvtRpcRegisterLogQuery_EvtRpcQueryNext(log_name, query)
    for event in xml_event:
        data = even_conn.parse_xml(event)
        subject_username = data['SubjectUserName']
        subject_domainname = data['SubjectDomainName']
        target_username = data['TargetUserName']
        target_domainname = data['TargetDomainName']
        process_name = data['ProcessName']
        ip_address = data['IpAddress']

        if (filter_results and re.match(data['Computer'], target_username) or re.match(r'^(Font Driver Host|Window Manager)$', target_domainname)):
            continue

        if user_regex is not None and not re.match(user_regex, target_username):
            continue

        yield ExplicitLogonEvents(subject_username, subject_domainname, target_username, target_domainname, process_name, ip_address, data['TimeCreated.SystemTime'])
    
def format_results(logon):
    target_user = f'{logon.TargetDomain}\\{logon.TargetUser}'
    subject_user = f'{logon.SubjectDomain}\\{logon.SubjectUser}'
    unique_cred = f'{target_user},{logon.Process},{subject_user},{logon.IpAddress}'
    utc_dt = datetime.fromisoformat(logon.TimeCreatedUtc).replace(tzinfo=timezone.utc)
    formatted_time = utc_dt.astimezone().strftime("%m/%d/%Y %I:%M %p")
    print(f'{formatted_time},{unique_cred}')

def command_base(options):
    command = 'ExplicitLogonEvents'
    description = 'Explicit Logon events (Event ID 4648) from the security event log. Default of 7 days, argument == last X days'
    command_group = ['misc', 'remote', 'test']

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
        for events in get_explicit_logon_events(even_conn, args):
            if events is not None:
                format_results(events)
    except KeyboardInterrupt:
        even_conn.close()
    except Exception as e:
        print(e)

    even_conn.close()