
import uuid
from lib import SMBHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class KeePass:
    def __init__(self, filename: str, lastaccessed: str, lastmodified: str, masterkeyguid: str, size: str):
        self.FileName = filename
        self.LastAccessed = lastaccessed
        self.LastModified =  lastmodified
        self.MasterKeyGuid = masterkeyguid
        self.Size = size

def get_keepass(smb_conn):
    share = "C$"
    path = "\\Users" 

    if smb_conn.connect():
        directory_listing = smb_conn.list_directory(share, path)
        for f in directory_listing:
            if f.is_directory():
                if f.get_longname() == '.' or f.get_longname() == '..' or f.get_longname() == 'Public' or f.get_longname() == 'Default' or f.get_longname() == 'Default User' or f.get_longname() == 'All Users':
                    continue

                user = str(f.get_longname())
                kp_config = f'{path}\\{user}\\AppData\\Roaming\\KeePass\\KeePass.config.xml'
                if smb_conn.file_exists(share, kp_config):
                    found_file = f'C:\\{user}\\AppData\\Roaming\\KeePass\\KeePass.config.xml'
                    last_accessed = smb_conn.get_last_access_time(share, kp_config)
                    last_modified = smb_conn.get_last_write_time(share, kp_config)
                    conf_size = smb_conn.get_file_size(share, kp_config)
                    yield KeePass(found_file, last_accessed, last_modified, '', conf_size)

                proc_key = f'{path}\\{user}\\AppData\\Roaming\\KeePass\\ProtectedUserKey.bin'
                if smb_conn.file_exists(share, proc_key):
                    found_file = f'C:\\{user}\\AppData\\Roaming\\KeePass\\ProtectedUserKey.bin'
                    last_accessed = smb_conn.get_last_access_time(share, proc_key)
                    last_modified = smb_conn.get_last_write_time(share, proc_key)
                    key_size = smb_conn.get_file_size(share, proc_key)

                    # TODO: Test this to make sure it actually gets the GUID
                    blob_bytes = smb_conn.read_file_raw(share, proc_key)
                    offset = 24
                    guid_masterkey_bytes = blob_bytes[offset:offset+16]
                    guid_masterkey = uuid.UUID(bytes_le=guid_masterkey_bytes)
                    guid_string = f"{{{str(guid_masterkey)}}}"
                    yield KeePass(found_file, last_accessed, last_modified, guid_string, key_size)


def command_base(options):
    command = 'KeePass'
    description = 'Finds KeePass configuration files'
    command_group = ['user', 'remote']

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        smb_conn = SMBHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        for kp in get_keepass(smb_conn):
            if kp is not None:
                PrintHandler.print_props(kp)
                print()
    except KeyboardInterrupt:
        smb_conn.close()
    except Exception as e:
        print(e)
        
    smb_conn.close()