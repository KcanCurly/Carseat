
from io import BytesIO
import re
from lib import PrintHandler
from lib import SMBHandler
from impacket.examples.utils import parse_target
from impacket.smbconnection import SessionError

class ChromiumHistory:
    def __init__(self, username: str, filepath: str, urls: list):
        self.UserName = username
        self.FilePath = filepath
        self.URLs = urls

def get_chromium_history(smb_conn):
    share = "C$"
    user_path = "\\Users" 
    path_list = [
        "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\",
        "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\",
        "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\",
        "\\AppData\\Roaming\\Opera Software\\Opera Stable\\"
    ]
    urls = []
    url_regex = re.compile(rb'(http|ftp|https|file)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?')

    if smb_conn.connect():
        directory_listing = smb_conn.list_directory(share, user_path)
        for f in directory_listing:
            if f.is_directory():
                if f.get_longname() == '.' or f.get_longname() == '..' or f.get_longname() == 'Public' or f.get_longname() == 'Default' or f.get_longname() == 'Default User' or f.get_longname() == 'All Users':
                    continue
                user = f.get_longname()
                for path in path_list:
                    directories = str(f.get_longname())
                    ch_hist_path = f'\\Users\\{directories}{path}'
                    if smb_conn.file_exists(share, ch_hist_path):
                        try:
                            hist_data = smb_conn.read_special(share, f'{ch_hist_path}\\History')
                            fh = BytesIO(hist_data)
                            for line in fh:
                                match = url_regex.search(line)
                                if match:
                                    url = match.group(0).decode('utf-8', errors='replace').strip()
                                    urls.append(url)
                        except SessionError as e:
                            if e.getErrorCode() == 0xc0000043:
                                raise Exception(f"IO exception, history file likely in use (i.e. browser is likely running): {e}")
                        except Exception as e:
                            print(e)
                            continue
                        yield ChromiumHistory(user, ch_hist_path, urls)

def format_results(history):
    print(f'History ({history.FilePath}):\n')

    for url in history.URLs:
        print(f'  {url}')
    print()

def command_base(options):
    command = 'ChromiumHistory'
    description = 'Parses any found Chrome/Edge/Brave/Opera history files'
    command_group = ['misc', 'chromium', 'remote']
    
    domain, username, password, address = parse_target(options.target)
    
    PrintHandler.show_banner(command)
    try:
        smb_conn = SMBHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        for history in get_chromium_history(smb_conn):
            if history is not None:
                format_results(history)
    except KeyboardInterrupt:
        smb_conn.close()
    except Exception as e:
        print(e)

    smb_conn.close()