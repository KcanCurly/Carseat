
import re
from datetime import datetime, timedelta, timezone
from lib import EVENHandler
from lib import PrintHandler
from lib import MiscUtil
from impacket.examples.utils import parse_target

class PowerShellEvents:
    def __init__(self, timecreated: datetime, eventid: int, userid: str, match: str, context: str):
        self.TimeCreated = timecreated
        self.EventId = eventid
        self.UserId = userid
        self.Match = match
        self.Context = context

def get_powershell_events(even_conn, args):
    print('Searching script block logs (EID 4104) for sensitive data.\n')
    context = 3
    powershell_logs = [
        "Microsoft-Windows-PowerShell/Operational",
        "Windows PowerShell"
    ]

    ps_regex = MiscUtil.get_process_cmdline_regex()

    if len(args) >= 1:
        all_args = ' '.join(args)
        ps_regex = [re.compile(all_args, re.IGNORECASE | re.MULTILINE)]
    
    for log_name in powershell_logs:
        query = f"*[System/EventID=4104]"
        xml_event = even_conn.EvtRpcRegisterLogQuery_EvtRpcQueryNext(log_name, query)
        for event in xml_event:
            data = even_conn.parse_xml(event)
            script_block = data['ScriptBlockText']
            context_lines = []
            for regex in ps_regex:
                match = regex.search(script_block)
                if not match:
                    continue
                
                context_lines = []
                script_block_parts = script_block.split('\n')
                
                for i in range(len(script_block_parts)):
                    if match.group() not in script_block_parts[i]:
                        continue

                    printed = 0
                    j = 1
                    while i - j > 0 and printed < context:
                        if script_block_parts[i - j].strip() == "":
                            j += 1
                            continue
                        context_lines.append(script_block_parts[i - j].strip())
                        printed += 1
                        j += 1
                    
                    printed = 0
                    context_lines.append(match.group().strip())
                    
                    j = 1
                    while printed < context and i + j < len(script_block_parts):
                        if script_block_parts[i + j].strip() == "":
                            j += 1
                            continue
                        context_lines.append(script_block_parts[i + j].strip())
                        printed += 1
                        j += 1
                        
                    break
                
                context_joined = "\n".join(context_lines)
                yield PowerShellEvents(data['TimeCreated.SystemTime'], data['EventID'], data['Security.UserID'], match.group(), context_joined)


def format_results(event):
    print()

def command_base(options):
    command = 'PowerShellEvents'
    description = 'PowerShell script block logs (4104) with sensitive data'
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
        for events in get_powershell_events(even_conn, args):
            if events is not None:
                PrintHandler.print_props(events)
                print()
    except KeyboardInterrupt:
        even_conn.close()
    except Exception as e:
        print(e)

    even_conn.close()