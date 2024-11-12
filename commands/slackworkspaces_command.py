
import json
from datetime import datetime, timezone
from lib import SMBHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class Workspace:
    def __init__(self, name: str = None, domain: str = None, id: str = None):
        self.Name = name
        self.Domain = domain
        self.ID = id

class SlackWorkspaces:
    def __init__(self, username: str, workspaces: list):
        self.UserName = username
        self.Workspaces = workspaces

def get_slack_workspaces(smb_conn):
    share = "C$"
    user_path = "\\Users" 

    if smb_conn.connect():
        directory_listing = smb_conn.list_directory(share, user_path)
        for f in directory_listing:
            if f.is_directory():
                if f.get_longname() == '.' or f.get_longname() == '..' or f.get_longname() == 'Public' or f.get_longname() == 'Default' or f.get_longname() == 'Default User' or f.get_longname() == 'All Users':
                    continue
                user = str(f.get_longname())
                slack_workspace_base = f'{user_path}\\{user}\\AppData\\Roaming\\Slack\\storage'
                sw = 'slack-workspaces'
                if smb_conn.file_exists(share, f'{slack_workspace_base}\\{sw}'):
                    workspaces = []
                    content = smb_conn.show_file_content(share, slack_workspace_base, sw)
                    deserialized = json.loads(content)
                    for _, first_level_dict in deserialized.items():
                        for _, dl in first_level_dict.items():
                            workspace = Workspace()
                            if "name" in dl:
                                workspace.Name = str(dl["name"])
                            if "domain" in dl:
                                workspace.Domain = str(dl["domain"])
                            if "id" in dl:
                                workspace.ID = str(dl["id"])

                            workspaces.append(workspace)
                            
                    yield SlackWorkspaces(user, workspace)

def format_results(slack):
    print(f'  Workspaces ({slack.UserName}):\n')

    for workspace in slack.Workspaces:
        print(f"    Name   : {workspace.Name}")
        print(f"    Domain : {workspace.Domain}")
        print(f"    ID     : {workspace.ID}")
    print()

def command_base(options):
    command = 'SlackWorkspaces'
    description = 'Parses any found \'slack-workspaces\' files'
    command_group = ['user', 'remote']

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        smb_conn = SMBHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        for workspaces in get_slack_workspaces(smb_conn):
            if workspaces is not None:
                format_results(workspaces)
                print()
    except KeyboardInterrupt:
        smb_conn.close()
    except Exception as e:
        print(e)

    smb_conn.close()