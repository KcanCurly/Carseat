
import re
from lib import SMBHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class DPAPIMasterKeys:
    def __init__(self, folder: str, masterkeys: list):
        self.Folder = folder
        self.MasterKeys = masterkeys

class MasterKey:
    def __init__(self, filename: str, lastaccessed: str, lastmodified: str):
        self.FileName = filename
        self.LastAccessed = lastaccessed
        self.LastModified = lastmodified

def get_dpapi_masterkeys(smb_conn):
    share = "C$"
    path = "\\Users"
    masterkeys = []
    
    mkey = re.compile(r'[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}')
    directory_listing = smb_conn.list_directory(share, path)
    for f in directory_listing:
        if f.is_directory():
            if f.get_longname() == '.' or f.get_longname() == '..' or f.get_longname() == 'Public' or f.get_longname() == 'Default' or f.get_longname() == 'Default User' or f.get_longname() == 'All Users':
                continue

            username = f.get_longname()
            dpapi_basepath = f'{path}\\{username}\\AppData\\Roaming\\Microsoft\\Protect\\'
            if not smb_conn.file_exists(share, dpapi_basepath):
                continue

            dpapi_listing = smb_conn.list_directory(share, dpapi_basepath)
            for dirs in dpapi_listing:
                if dirs.is_directory():
                    if dirs.get_longname() == '.' or dirs.get_longname() == '..':
                        continue
                    mk_dir = f'{dpapi_basepath}{dirs.get_longname()}'
                    fixed_dir = f'C:{mk_dir}'
                    keys = []
                    files = smb_conn.list_directory(share, mk_dir)
                    for file in files:
                            if not file.is_directory():
                                if not mkey.match(str(file.get_longname())):
                                    continue
                                mk_name = file.get_longname()
                                key_path = f'{mk_dir}\\{mk_name}'
                                mk_lastaccessed = smb_conn.get_last_access_time(share, key_path)
                                masterkey = MasterKey(mk_name, mk_lastaccessed, mk_lastaccessed)
                                keys.append(masterkey)
                    yield DPAPIMasterKeys(fixed_dir, keys)

def format_results(dpapi):
    print(f'  Folder : {dpapi.Folder}\n')
    print('    LastAccessed              LastModified              FileName')
    print('    ------------              ------------              --------')

    for k in dpapi.MasterKeys:
        print(f'    {k.LastAccessed}    {k.LastModified}    {k.FileName}')
    print()    

def print_extra():
    print('\n  [*] Use the Mimikatz "dpapi::masterkey" module with appropriate arguments (/pvk or /rpc) to decrypt')
    print('  [*] You can also extract many DPAPI masterkeys from memory with the Mimikatz "sekurlsa::dpapi" module')
    print('  [*] You can also use SharpDPAPI for masterkey retrieval.')

def command_base(options):
    command = 'DpapiMasterKeys'
    description = 'List DPAPI master keys'
    command_group = ['user', 'remote']

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        smb_conn = SMBHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        for mks in get_dpapi_masterkeys(smb_conn):
            if mks is not None:
                format_results(mks)
        print_extra()
    except KeyboardInterrupt:
        smb_conn.close()
    except Exception as e:
        print(e)

    smb_conn.close()
