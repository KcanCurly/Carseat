
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class ProcessOwner:
    def __init__(self, processname: str, processid: str, owner: str):
        self.ProcessName = processname
        self.ProcessID = processid
        self.Owner = owner

def get_process_owners(wmi_conn):
    wmi_data = wmi_conn.get_wmi_object('SELECT * FROM Win32_Process WHERE SessionID != 0')

    for proc in wmi_data:
        try:
            p = proc.GetOwner()
            properties = proc.getProperties()
            data = wmi_conn.parse_wmi(properties)
            if p.ReturnValue == 0:
                user = p.User
                domain = p.Domain
        except:
            pass
        owner = ''
        if user is not None:
            owner = f'{domain}\\{user}'
        yield ProcessOwner(data['Name'], data['ProcessId'], owner)
        
def format_results(process):
    print(f" {process.ProcessName:<50} {process.ProcessID:<10} {process.Owner}");

def command_base(options):
    command = 'ProcessOwners'
    description = 'Running non-session 0 process list with owners. For remote use.'
    command_group = ['misc', 'remote']
    wmi_namespace = "//./root/CIMv2"
    
    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for po in get_process_owners(wmi_conn):
            if po is not None:
                format_results(po)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()
    