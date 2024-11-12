
from datetime import datetime, timedelta, timezone
from lib import EVENHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class PoweredOnEvent:
    def __init__(self, dateutc: datetime, description: str):
        self.DateUtc = dateutc
        self.Description = description

def get_powered_on_events(even_conn, args):
    log_name = 'System'
    last_days = 7

    if len(args) >= 1:
        try:
            last_days = int(args[0])
        except (TypeError, ValueError):
            print('ERROR: Argument is not an integer')
            return

    start_time = datetime.now() - timedelta(days=last_days)
    end_time = datetime.now()
    start_time_utc = start_time.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    end_time_utc = end_time.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    query = f"((*[System[(EventID=12 or EventID=13) and Provider[@Name='Microsoft-Windows-Kernel-General']]] or *[System/EventID=42]) or (*[System/EventID=6008]) or (*[System/EventID=1] and *[System[Provider[@Name='Microsoft-Windows-Power-Troubleshooter']]])) and *[System[TimeCreated[@SystemTime >= '{start_time_utc}']]] and *[System[TimeCreated[@SystemTime <= '{end_time_utc}']]]"
    
    print(f"Collecting kernel boot (EID 12) and shutdown (EID 13) events from the last {last_days} days\n")
    print("Powered On Events (Time is local time)")

    xml_event = even_conn.EvtRpcRegisterLogQuery_EvtRpcQueryNext(log_name, query)
    for data in xml_event:
        event = even_conn.parse_xml(data)
        print(event)
        action = None
        if event['Id'] == 1:
            action = 'awake'
        elif event['Id']  == 12:
            action = 'startup'
        elif event['Id']  == 13:
            action = 'shutdown'
        elif event['Id']  == 42:
            action = 'sleep'
        elif event['Id']  == 6008:
            action = 'shutdown(UnexpectedShutdown)'

        yield PoweredOnEvent(event['TimeCreated.SystemTime'], action)


def format_results(event):
    print(f"  {event.DateUtc:<23} :  {event.Description}")

def command_base(options):
    command = 'PoweredOnEvents'
    description = 'Reboot and sleep schedule based on the System event log EIDs 1, 12, 13, 42, and 6008. Default of 7 days, argument == last X days.'
    command_group = ['system', 'remote']

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
        for events in get_powered_on_events(even_conn, args):
            if events is not None:
                format_results(events)
    except KeyboardInterrupt:
        even_conn.close()
    except Exception as e:
        print(e)

    even_conn.close()