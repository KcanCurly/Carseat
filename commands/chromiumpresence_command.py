

from lib import WMIHandler
from lib import SMBHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class ChromiumPresence:
    def __init__(self, folder: str, historylastmodified: str, cookieslastmodified: str, logindatalastmodified: str, chromeversion: str):
        self.Folder = folder
        self.HistoryLastModified = historylastmodified
        self.CookiesLastModified = cookieslastmodified
        self.LoginDataLastModified = logindatalastmodified
        self.ChromeVersion = chromeversion

def get_chrome_presence(wmi_conn, smb_conn):
    share = "C$"
    path = "\\Users"
    path_list = [
        "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\",
        "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\",
        "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\",
        "\\AppData\\Roaming\\Opera Software\\Opera Stable\\"
    ]

    try:
        chrome_path = wmi_conn.get_string_value('HKLM', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe', '')
        if len(chrome_path) > 2 and chrome_path[1] == ':' and chrome_path[2] == '\\':
            chrome_path = chrome_path[3:]
        if chrome_path is not None:
            if smb_conn.connect():
                chrome_version = smb_conn.get_version_info(share, chrome_path)

        directory_listing = smb_conn.list_directory(share, path)
        for f in directory_listing:
            if f.is_directory():
                if f.get_longname() == '.' or f.get_longname() == '..' or f.get_longname() == 'Public' or f.get_longname() == 'Default' or f.get_longname() == 'Default User' or f.get_longname() == 'All Users':
                    continue
                
                for path in path_list:
                    directories = str(f.get_longname())
                    ch_bm_path = f'\\Users\\{directories}{path}'
                    chrome_base = f'C:{ch_bm_path}'
                    chrome_history = f'{ch_bm_path}History'
                    chrome_cookies = f'{ch_bm_path}Cookies'
                    chrome_logindata = f'{ch_bm_path}LoginData'
                    history = smb_conn.get_last_write_time(share, chrome_history)
                    cookies = smb_conn.get_last_write_time(share, chrome_cookies)
                    login_data = smb_conn.get_last_write_time(share, chrome_logindata)

                    if history is not None or cookies is not None or login_data is not None:
                        yield ChromiumPresence(chrome_base, history, cookies, login_data, chrome_version)
    except:
        return None

def format_results(chrome):
    if chrome.Folder:
        print(f'\r\n {chrome.Folder}\n')

    if chrome.HistoryLastModified:
        print(f'    \'History\'     ({chrome.HistoryLastModified})  :  Run the \'ChromiumHistory\' command')
    if chrome.CookiesLastModified:
        print(f'    \'Cookies\'     ({chrome.CookiesLastModified})  :  Run SharpDPAPI/SharpChrome or the Mimikatz "dpapi::chrome" module')
    if chrome.LoginDataLastModified:
        print(f'    \'Login Data\'  ({chrome.LoginDataLastModified})  :  Run SharpDPAPI/SharpChrome or the Mimikatz "dpapi::chrome" module')
    if 'Google' in chrome.Folder :
        print(f'     Chrome Version                         :  {chrome.ChromeVersion}')
        if chrome.ChromeVersion and chrome.ChromeVersion.startswith("8"):
            print('         Version is 80+, new DPAPI scheme must be used')
    
def command_base(options):
    command = 'ChromiumPresence'
    description = 'Checks if interesting Chrome/Edge/Brave/Opera files exist'
    command_group = ['user', 'chromium', 'remote']
    wmi_namespace = "//./root/CIMv2"

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        smb_conn = SMBHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        for chrome_presence in get_chrome_presence(wmi_conn, smb_conn):
            if chrome_presence is not None:
                format_results(chrome_presence)
    except KeyboardInterrupt:
        wmi_conn.close()
        smb_conn.close()  
    except Exception as e:
        print(e)


    wmi_conn.close()
    smb_conn.close()