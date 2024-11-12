
import re
from datetime import datetime, timedelta, timezone
from lib import EVENHandler
from lib import PrintHandler
from lib import MiscUtil
from impacket.examples.utils import parse_target

class ProcessCreationEvent:
    def __init__(self, timecreatedutc: datetime, eventid: int, user: str, match: str):
        self.TimeCreatedUtc = timecreatedutc
        self.EventID = eventid
        self.User = user
        self.Match = match

def get_process_creation_events(even_conn, args):
    print('Searching process creation logs (EID 4688) for sensitive data')
    print('Format: Date(Local time),User,Command line.\n')

    proc_regex = MiscUtil.get_process_cmdline_regex()

    if len(args) >= 1:
        all_args = ' '.join(args)
        proc_regex = [re.compile(all_args, re.IGNORECASE | re.MULTILINE)]

    log_name = 'Security'
    query = f"*[System/EventID=4688]"
    xml_event = even_conn.EvtRpcRegisterLogQuery_EvtRpcQueryNext(log_name, query)
    for event in xml_event:
        event_detail = even_conn.parse_xml(event)

        user = str(event_detail['TargetUserName'])
        command_line = str(event_detail['CommandLine'])

        for reg in proc_regex:
            m = reg.search(command_line)
            if m:
                time_created = event_detail['TimeCreated.SystemTime']
                if time_created:
                    time_created = time_created.astimezone(datetime.timezone.utc)
                
                yield ProcessCreationEvent(time_created, event_detail['EventID'], user, m)

def format_results(event):
    print(f'  {event.TimeCreatedUtc:<22}  {event.User:<30} {event.Match}')

def command_base(options):
    command = 'ProcessCreationEvents'
    description = 'Process creation logs (4688) with sensitive data'
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
        for events in get_process_creation_events(even_conn, args):
            if events is not None:
                format_results(events)
    except KeyboardInterrupt:
        even_conn.close()
    except Exception as e:
        print(e)

    even_conn.close()