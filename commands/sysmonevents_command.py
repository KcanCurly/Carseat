
import re
from datetime import datetime
from lib import EVENHandler
from lib import PrintHandler
from lib import MiscUtil
from impacket.examples.utils import parse_target

class SysmonEvent:
    def __init__(self, timecreated: datetime, eventid: int, username: str, match: str):
        self.TimeCreated = timecreated
        self.EventId = eventid
        self.UserName = username
        self.Match = match

def get_sysmon_events(even_conn, args):
    print('Searching Sysmon process creation logs (Sysmon ID 1) for sensitive data.\n')

    sysmon_regex = MiscUtil.get_process_cmdline_regex()
    if len(args) >= 1:
        all_args = ' '.join(args)
        sysmon_regex = [re.compile(all_args, re.IGNORECASE | re.MULTILINE)]

    log_name = 'Microsoft-Windows-Sysmon/Operational'
    query = f"*[System/EventID=1]"
    #if sysmon isnt installed this will likely throw an exception
    #not a great way to catch the exception currently
    xml_event = even_conn.EvtRpcRegisterLogQuery_EvtRpcQueryNext(log_name, query)
    i = 0
    for event in xml_event:
        data = even_conn.parse_xml(event)
        i += 1
        command_line = str(data['CommandLine']).strip()
        if command_line != "":
            for reg in sysmon_regex:
                m = reg.search(command_line)
                if m:
                    user_name = str(data['User']).strip()
                    yield SysmonEvent(data['TimeCreated.SystemTime'], data['EventId'], user_name, m.group())

def command_base(options):
    command = 'SysmonEvents'
    description = 'Sysmon process creation logs (1) with sensitive data'
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
        for events in get_sysmon_events(even_conn, args):
            if events is not None:
                PrintHandler.print_props(events)
    except KeyboardInterrupt:
        even_conn.close()
    except Exception as e:
        print(e)

    even_conn.close()