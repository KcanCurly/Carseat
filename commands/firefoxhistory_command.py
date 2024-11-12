from io import BytesIO
import re
from lib import SMBHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class FirefoxHistory:
    def __init__(self, username: str, history: list):
        self.UserName = username
        self.History = history

def get_firefox_history(smb_conn):
    share = "C$"
    user_path = "\\Users" 
    hist_regex = re.compile(rb'(http|ftp|https|file)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?')

    if smb_conn.connect():
        directory_listing = smb_conn.list_directory(share, user_path)
        for f in directory_listing:
            if f.is_directory():
                if f.get_longname() == '.' or f.get_longname() == '..' or f.get_longname() == 'Public' or f.get_longname() == 'Default' or f.get_longname() == 'Default User' or f.get_longname() == 'All Users':
                    continue
                user = f.get_longname()
                firefox_hist_path = f'\\Users\\{user}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles'
                if smb_conn.file_exists(share, firefox_hist_path):
                    history = []
                    directories = smb_conn.list_directory(share, firefox_hist_path)
                    for directory in directories:
                        if directory.is_directory():
                            ff_history_file = f'{firefox_hist_path}\\{directory.get_longname()}\\places.sqlite'
                            if smb_conn.file_exists(share, ff_history_file):
                                try:
                                    hist_data = smb_conn.read_special(share, ff_history_file)
                                    fh = BytesIO(hist_data)
                                    for line in fh:
                                        match = hist_regex.search(line)
                                        if match:
                                            url = match.group(0).decode('utf-8', errors='replace').strip()
                                            history.append(url)
                                except Exception as e:
                                    print(e)
                                    continue
                    yield FirefoxHistory(user, history)

def format_results(history):
    print(f'\n    History ({history.UserName}):\n')

    for history in history.History:
        print(f'       {history}')
    print()

def command_base(options):
    command = 'FirefoxHistory'
    description = 'Parses any found FireFox history files'
    command_group = ['user', 'remote']

    domain, username, password, address = parse_target(options.target)
    
    PrintHandler.show_banner(command)
    try:
        smb_conn = SMBHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        for history in get_firefox_history(smb_conn):
            if history is not None:
                format_results(history)
    except KeyboardInterrupt:
        smb_conn.close()
    except Exception as e:
        print(e)

    smb_conn.close()