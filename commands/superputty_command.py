
import xml.etree.ElementTree as ET
from lib import SMBHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class SuperPuttyConfig:
    def __init__(self, filepath: str, sessionid: str, sessionname: str, host: str, port: str, protocol: str, username: str, extraargs: str):
        self.FilePath = filepath
        self.SessionID = sessionid
        self.SessionName = sessionname
        self.Host = host
        self.Port = port
        self.Protocol = protocol
        self.UserName = username
        self.ExtraArgs = extraargs

class SuperPutty:
    def __init__(self, username: str, configs: list):
        self.UserName = username
        self.Configs = configs

def get_super_putty(smb_conn):
    share = "C$"
    user_path = "\\Users" 

    if smb_conn.connect():
        directory_listing = smb_conn.list_directory(share, user_path)
        for f in directory_listing:
            if f.is_directory():
                if f.get_longname() == '.' or f.get_longname() == '..' or f.get_longname() == 'Public' or f.get_longname() == 'Default' or f.get_longname() == 'Default User' or f.get_longname() == 'All Users':
                    continue
                user = str(f.get_longname())

                configs = []
                path = f'{user_path}\\{user}\\Documents\\SuperPuTTY'
                xml_file = 'Sessions.xml'
                if not smb_conn.file_exists(share, f'{path}\\{xml_file}'):
                    continue
                doc = smb_conn.show_file_content(share, path, xml_file)
                root = ET.fromstring(doc)
                sessions = root.findall(".//SessionData")
                if not sessions:
                    continue
                for session in sessions:
                    file_path = path
                    session_id = session.get('SessionId')
                    session_name = session.get("SessionName")
                    host = session.get("Host")
                    port = session.get("Port")
                    protocol = session.get("Proto")
                    username = session.get("Username")
                    extra_args = session.get("ExtraArgs")

                    config = SuperPuttyConfig(file_path, session_id, session_name, host, port, protocol, username, extra_args)
                    configs.append(config)

                if len(configs) > 0:
                    yield SuperPutty(user, configs)

def format_results(super_putty):
    print(f'  SuperPutty Configs ({super_putty.UserName}):\n')

    for config in super_putty.Configs:
        print(f"    FilePath    : {config.FilePath}")
        print(f"    SessionID   : {config.SessionID}")
        print(f"    SessionName : {config.SessionName}")
        print(f"    Host        : {config.Host}")
        print(f"    Port        : {config.Port}")
        print(f"    Protocol    : {config.Protocol}")
        print(f"    Username    : {config.UserName}")
        if config.ExtraArgs:
            print(f'    ExtraArgs   : {config.ExtraArgs}')
    print()

def command_base(options):
    command = 'SuperPutty'
    description = 'SuperPutty configuration files"'
    command_group = ['user', 'remote']

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        smb_conn = SMBHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        for super_putty in get_super_putty(smb_conn):
            if super_putty is not None:
                format_results(super_putty)
    except KeyboardInterrupt:
        smb_conn.close()
    except Exception as e:
        print(e)

    smb_conn.close()