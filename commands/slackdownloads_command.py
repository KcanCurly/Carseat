
import json
from datetime import datetime, timezone
from lib import SMBHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class Download:
    def __init__(self, teamid: str = None, userid: str = None, downloadpath: str = None, datetime: datetime = None):
        self.TeamID = teamid
        self.UserID = userid
        self.DownloadPath = downloadpath
        self.StartTime = datetime

class SlackDownloads:
    def __init__(self, username: str, downloads: list):
        self.UserName = username
        self.Downloads = downloads

def get_slack_downloads(smb_conn):
    share = "C$"
    user_path = "\\Users" 

    if smb_conn.connect():
        directory_listing = smb_conn.list_directory(share, user_path)
        for f in directory_listing:
            if f.is_directory():
                if f.get_longname() == '.' or f.get_longname() == '..' or f.get_longname() == 'Public' or f.get_longname() == 'Default' or f.get_longname() == 'Default User' or f.get_longname() == 'All Users':
                    continue
                user = str(f.get_longname())
                slack_downloads_base = f'{user_path}\\{user}\\AppData\\Roaming\\Slack\\storage'
                sd = 'slack-downloads'
                if smb_conn.file_exists(share, f'{slack_downloads_base}\\{sd}'):
                    downloads = []
                    content = smb_conn.show_file_content(share, slack_downloads_base, sd)
                    deserialized = json.loads(content)
                    for _, first_level_dict in deserialized.items():
                        for _, dl in first_level_dict.items():
                            download = Download()
                            if "teamId" in dl:
                                download.TeamID = str(dl["teamId"])
                            if "userId" in dl:
                                download.UserID = str(dl["userId"])
                            if "downloadPath" in dl:
                                download.DownloadPath = str(dl["downloadPath"])
                            if "startTime" in dl:
                                try:
                                    download.StartTime = datetime.fromtimestamp(int(dl["startTime"]), tz=timezone.utc)
                                except:
                                    pass
                            downloads.append(download)
                            
                    yield SlackDownloads(user, downloads)

def format_results(s_downloads):
    print(f'  Downloads ({s_downloads.UserName}):\n')

    for download in s_downloads.Downloads:
        print(f"    TeamID       : {download.TeamID}")
        print(f"    UserId       : {download.UserID}")
        print(f"    DownloadPath : {download.DownloadPath}")
        print(f"    StartTime    : {download.StartTime}\n")
    print()

def command_base(options):
    command = 'SlackDownloads'
    description = 'Parses any found \'slack-downloads\' files'
    command_group = ['user', 'remote']

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        smb_conn = SMBHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        for downloads in get_slack_downloads(smb_conn):
            if downloads is not None:
                format_results(downloads)
                print()
    except KeyboardInterrupt:
        smb_conn.close()
    except Exception as e:
        print(e)

    smb_conn.close()