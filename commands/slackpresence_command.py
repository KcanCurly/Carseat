
from datetime import datetime
from lib import SMBHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class SlackPresence:
    def __init__(self, folder: str, cookieslastmodified: datetime, workspaceslastmodified: datetime, downloadslastmodified: datetime):
        self.Folder = folder
        self.CookiesLastModified = cookieslastmodified
        self.WorkspacesLastModified = workspaceslastmodified
        self.DownloadsLastModified = downloadslastmodified

def get_slack_presence(smb_conn):
    share = "C$"
    user_path = "\\Users" 

    if smb_conn.connect():
        directory_listing = smb_conn.list_directory(share, user_path)
        for f in directory_listing:
            if f.is_directory():
                if f.get_longname() == '.' or f.get_longname() == '..' or f.get_longname() == 'Public' or f.get_longname() == 'Default' or f.get_longname() == 'Default User' or f.get_longname() == 'All Users':
                    continue
                user = str(f.get_longname())
                slack_base = f'{user_path}\\{user}\\AppData\\Roaming\\Slack'
                if not smb_conn.file_exists(share, slack_base):
                    continue
                cookies_last_write_time = datetime.min
                workspace_last_write_time = datetime.min
                downloads_last_write_time = datetime.min

                cookie_base = f'{user_path}\\{user}\\AppData\\Roaming\\Slack\\Cookies'
                if smb_conn.file_exists(share, cookie_base):
                    cookies_last_write_time = smb_conn.get_last_write_time(share, cookie_base)
                workspace_base = f'{user_path}\\{user}\\AppData\\Roaming\\Slack\\storage\\slack-workspaces'
                if smb_conn.file_exists(share, workspace_base):
                    workspace_last_write_time = smb_conn.get_last_write_time(share, workspace_base)
                downloads_base = f'{user_path}\\{user}\\AppData\\Roaming\\Slack\\storage\\slack-downloads'
                if smb_conn.file_exists(share, downloads_base):
                    downloads_last_write_time = smb_conn.get_last_write_time(share, downloads_base)
                
                if cookies_last_write_time is not None or workspace_last_write_time is not None or downloads_last_write_time is not None:
                    yield SlackPresence(slack_base, cookies_last_write_time, workspace_last_write_time, downloads_last_write_time)

def format_results(slack):
    print(f'  {slack.Folder}\n')
    if slack.CookiesLastModified is not datetime.min:
        print(f"    'Cookies'                   ({slack.CookiesLastModified})  :  Download the 'Cookies' and 'storage\\slack-workspaces' files to clone Slack access")
    if slack.WorkspacesLastModified is not datetime.min:
        print(f"    '\\storage\\slack-workspaces' ({slack.WorkspacesLastModified})  :  Run the 'SlackWorkspaces' command")
    if slack.DownloadsLastModified is not datetime.min:
        print(f"    '\\storage\\slack-downloads'  ({slack.DownloadsLastModified})  :  Run the 'SlackDownloads' command")

def command_base(options):
    command = 'SlackPresence'
    description = 'Checks if interesting Slack files exist'
    command_group = ['user', 'remote']

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        smb_conn = SMBHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        for slack in get_slack_presence(smb_conn):
            if slack is not None:
                format_results(slack)
                print()
    except KeyboardInterrupt:
        smb_conn.close()
    except Exception as e:
        print(e)

    smb_conn.close()