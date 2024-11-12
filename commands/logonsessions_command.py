
from datetime import datetime
from enum import IntEnum
import re
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

 
class SECURITY_LOGON_TYPE(IntEnum):
    Interactive = 2
    Network = 3
    Batch = 4
    Service = 5
    Unlock = 7
    NetworkCleartext = 8
    NewCredentials = 9
    RemoteInteractive = 10
    CachedInteractive = 11

class LogonSession:
    def __init__(self, enumerationmethod: str, username: str, domain: str, logonid: str, logontype: str, authenticationpackage: str, starttime: str, logontime: str, logonserver: str, logonserverdnsdomain: str, userprincipalname: str, usersid: str):
        self.EnumerationMethod = enumerationmethod
        self.UserName = username
        self.Domain = domain
        self.LogonId = logonid
        self.LogonType = logontype
        self.AuthenticationPackage = authenticationpackage
        self.StartTime = starttime
        self.LogonTime = logontime
        self.LogonServer = logonserver
        self.LogonServerDnsDomain = logonserverdnsdomain
        self.UserPrincipalName = userprincipalname
        self.UserSID = usersid

def get_logon_sessions(wmi_conn):
    # TODO: Maybe implement LSA enumeration? More data?
    user_domain_regex = re.compile(r'Domain="(.*)",Name="(.*)"')
    logon_id_regex = re.compile(r'LogonId="(\d+)"')
    logon_map = {}

    wmi_data = wmi_conn.wmi_get('SELECT * FROM Win32_LoggedOnUser')
    for logged in wmi_data:
        data = wmi_conn.parse_wmi(logged)

        m = logon_id_regex.search(str(data["Dependent"]))
        if not m:
            continue

        logon_id = m.group(1)
        m2 = user_domain_regex.search(str(data["Antecedent"]))
        if not m2:
            continue
        
        domain = m2.group(1)
        user = m2.group(2)

        logon_map[logon_id] = [domain, user]

    wmi_data_two = wmi_conn.wmi_get('SELECT * FROM Win32_LogonSession')
    for sess in wmi_data_two:
        data_two = wmi_conn.parse_wmi(sess)

        user_domain = ["", ""]
        try:
            user_domain = logon_map[str(data_two["LogonId"])]
        except:
            pass
        
        domain = user_domain[0]
        user_name = user_domain[1]
        start_time = datetime.now().strftime("%m/%d/%Y %I:%M:%S %p") 
        logon_type = ""
    
        try:
            s_time = str(data_two["StartTime"])[:14]
            dt = datetime.strptime(s_time, "%Y%m%d%H%M%S")
            start_time = dt.strftime("%m/%d/%Y %I:%M:%S %p")
        except:
            pass
        
        try:            
            logon_type = SECURITY_LOGON_TYPE(int(data_two["LogonType"])).name
        except:
            pass

        yield LogonSession('WMI', user_name, domain, logon_id, logon_type, data_two['AuthenticationPackage'], start_time, '', '', '', '', '')
    return None

def command_base(options):
    command = 'LogonSessions'
    description = 'Windows logon sessions'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    print("Logon Sessions (via WMI)\r\n")
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for sessions in get_logon_sessions(wmi_conn):
            if sessions is not None:
                PrintHandler.print_props(sessions)
                print()
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()