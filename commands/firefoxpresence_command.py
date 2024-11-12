from io import BytesIO
from datetime import datetime
from lib import SMBHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class FirefoxPresence:
    def __init__(self, folder: str, historylastmodified: datetime, credentialfile3lastmodified: datetime, credentialfile4lastmodified: datetime):
        self.Folder = folder
        self.HistoryLastModified = historylastmodified
        self.CredentialFile3LastModified = credentialfile3lastmodified
        self.CredentialFile4LastModified = credentialfile4lastmodified

def get_firefox_presence(smb_conn):
    share = "C$"
    user_path = "\\Users" 

    if smb_conn.connect():
        directory_listing = smb_conn.list_directory(share, user_path)
        for f in directory_listing:
            if f.is_directory():
                if f.get_longname() == '.' or f.get_longname() == '..' or f.get_longname() == 'Public' or f.get_longname() == 'Default' or f.get_longname() == 'Default User' or f.get_longname() == 'All Users':
                    continue
                user = f.get_longname()
                firefox_base_path = f'\\Users\\{user}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles'
                if smb_conn.file_exists(share, firefox_base_path):
                    history_last_mod = datetime.min
                    credential_three_last_mod = datetime.min
                    credential_four_last_mod = datetime.min
                    
                    directories = smb_conn.list_directory(share, firefox_base_path)
                    for directory in directories:
                        if directory.is_directory():
                            fix_path = f'C:{firefox_base_path}\\{directory.get_longname()}'
                            ff_history_file = f'{firefox_base_path}\\{directory.get_longname()}\\places.sqlite'
                            if smb_conn.file_exists(share, ff_history_file):
                                try:
                                    history_last_mod = smb_conn.get_last_write_time(share, ff_history_file)
                                except Exception as e:
                                    print(e)
                                    continue

                            ff_cred_three = f'{firefox_base_path}\\{directory.get_longname()}\\key3.db'
                            if smb_conn.file_exists(share, ff_cred_three):
                                try:
                                    credential_three_last_mod = smb_conn.get_last_write_time(share, ff_cred_three)
                                except Exception as e:
                                    print(e)
                                    continue

                            ff_cred_four = f'{firefox_base_path}\\{directory.get_longname()}\\key4.db'
                            if smb_conn.file_exists(share, ff_cred_four):
                                try:
                                    credential_four_last_mod = smb_conn.get_last_write_time(share, ff_cred_four)
                                except Exception as e:
                                    print(e)
                                    continue
                            
                            if history_last_mod != datetime.min or credential_three_last_mod != datetime.min or credential_four_last_mod != datetime.min:
                                yield FirefoxPresence(fix_path, history_last_mod, credential_three_last_mod, credential_four_last_mod)

def format_results(firefox):
    print(f'  {firefox.Folder}\\\n')

    if firefox.HistoryLastModified != datetime.min:
        print(f"    'places.sqlite'  ({firefox.HistoryLastModified})  :  History file, run the 'FirefoxTriage' command")

    if firefox.CredentialFile3LastModified != datetime.min:
        print(f"    'key3.db'        ({firefox.CredentialFile3LastModified})  :  Credentials file, run SharpWeb (https://github.com/djhohnstein/SharpWeb)")
    
    if firefox.CredentialFile4LastModified != datetime.min:
        print(f"    'key4.db'        ({firefox.CredentialFile4LastModified})  :  Credentials file, run SharpWeb (https://github.com/djhohnstein/SharpWeb)")

def command_base(options):
    command = 'FirefoxPresence'
    description = 'Checks if interesting Firefox files exist'
    command_group = ['user', 'remote']

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        smb_conn = SMBHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        for firefox in get_firefox_presence(smb_conn):
            if firefox is not None:
                format_results(firefox)
    except KeyboardInterrupt:
        smb_conn.close()
    except Exception as e:
        print(e)

    smb_conn.close()