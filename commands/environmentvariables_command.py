
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class EnvironmentVariables:
    def __init__(self, username: str, name :str, value: str):
        self.UserName = username
        self.Name = name
        self.Value = value

def get_env_vars(wmi_conn):
    e_vars = []
    try:
        env_data = wmi_conn.wmi_get('Select UserName,Name,VariableValue from win32_environment')
    except Exception as e:
        return None
        
    for d in env_data:
        data = wmi_conn.parse_wmi(d)
        yield EnvironmentVariables(data['UserName'], data['Name'], data['VariableValue'])

    return e_vars

def format_result(env_obj):
    print(f"  {env_obj.UserName:<35} {env_obj.Name:<35} {env_obj.Value}")

def command_base(options):
    command = 'EnvironmentVariables'
    description = 'EnvironmentVariables'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"
    
    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for env_vars in get_env_vars(wmi_conn):
            if env_vars is not None:
                format_result(env_vars)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()