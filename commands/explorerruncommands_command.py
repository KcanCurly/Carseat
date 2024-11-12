
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class ExplorerRunCommands:
    def __init__(self, sid: str, commands :str):
        self.Sid = sid
        self.Commands = commands

class RunCommand:
    def __init__(self, key: str, value: str):
        self.Key = key
        self.Value = value

def get_explore_run_commands(wmi_conn):
    try:
        sids = wmi_conn.get_subkey_names('HKU', '')
        for sid in sids:
            if not sid.startswith('S-1-5') or sid.endswith('_Classes'):
                continue
            recent_commands = wmi_conn.get_registry_value('HKU', f'{sid}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU')
            if recent_commands is None or len(recent_commands) == 0:
                continue
            commands = []
            for k, v in recent_commands.items():
                c = RunCommand(k, v)
                commands.append(c)
            yield ExplorerRunCommands(sid, commands)
    except Exception as e:
        print(e)
        return None

def format_results(run_commands):
    print(f'\n  {run_commands.Sid} :')
    for rc in run_commands.Commands:
        print(f'    {rc.Key:<10} :  {rc.Value}')

def command_base(options):
    command = 'ExplorerRunCommands'
    description = 'Recent Explorer "run" commands'
    command_group = ['user', 'remote']
    wmi_namespace = "//./root/CIMv2"
    
    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for rcs in get_explore_run_commands(wmi_conn):
            if rcs is not None:
                format_results(rcs)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()