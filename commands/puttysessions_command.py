
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class PuttySessions:
    def __init__(self, sid: str, sessions: list):
        self.Sid = sid
        self.Sessions = sessions

def get_putty_sessions(wmi_conn):
    sids = wmi_conn.get_user_sids()
    for sid in sids:
        if not sid.startswith('S-1-5') or sid.endswith('_Classes'):
            continue
        subkeys = wmi_conn.get_subkey_names('HKU', f'{sid}\\Software\\SimonTatham\\PuTTY\\Sessions\\')

        sessions = []
        settings = {}
        for session_name in subkeys:
            settings = {
                "SessionName": session_name
            }

            keys = [
                "HostName",
                "UserName",
                "PublicKeyFile",
                "PortForwardings",
                "ConnectionSharing",
                "AgentFwd"
            ]

            for key in keys:
                if key == 'AgentFwd' or key == 'ConnectionSharing':
                    result = wmi_conn.get_dword_value('HKU', f'{sid}\\\\Software\\SimonTatham\\PuTTY\\Sessions\\{session_name}', key)
                else:
                    result = wmi_conn.get_string_value('HKU', f'{sid}\\\\Software\\SimonTatham\\PuTTY\\Sessions\\{session_name}', key)
                if result is not None and result != '':
                    settings[key] = result
            sessions.append(settings)
            if len(sessions) != 0:
                yield PuttySessions(sid, sessions)

def format_results(puttysessions):
    print(f'  {puttysessions.Sid} :\n')
    for sessions in puttysessions.Sessions:
        print(f'     {"SessionName":<20} : {sessions["SessionName"]}')

        for key in sessions.keys():
            if key != 'SessionName':
                print(f'     {key:<20} : {sessions[key]}')
        print()
    print()

def command_base(options):
    command = 'PuttySessions'
    description = 'Saved Putty configuration (interesting fields) and SSH host keys'
    command_group = ['user', 'remote']
    wmi_namespace = "//./root/CIMv2"
    
    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for sessions in get_putty_sessions(wmi_conn):
            if sessions is not None:
                format_results(sessions)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()