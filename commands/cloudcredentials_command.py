
from fileinput import filename
from lib import SMBHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class CloudCredentials:
    def __init__(self, credtype: str, filename: str, lastaccessed: str, lastmodified: str, size: str):
        self.Type = credtype
        self.FileName = filename
        self.LastAccessed = lastaccessed
        self.LastModified = lastmodified
        self.Size = size

def get_cloud_credentials(smb_conn):
    share = "C$"
    path = "\\Users" 

    google_locations = [
        "AppData\\Roaming\\gcloud\\credentials.db",
        "AppData\\Roaming\\gcloud\\legacy_credentials",
        "AppData\\Roaming\\gcloud\\access_tokens.db"
    ]

    azure_locations = [
        ".azure\\azureProfile.json",
        ".azure\\TokenCache.dat",
        ".azure\\AzureRMContext.json",
        "AppData\\Roaming\\Windows Azure Powershell\\TokenCache.dat",
        "AppData\\Roaming\\Windows Azure Powershell\\AzureRMContext.json"
    ]

    bluemix_locations = [
        ".bluemix\\config.json",
        ".bluemix\\.cf\\config.json"
    ]

    if smb_conn.connect():
        directory_listing = smb_conn.list_directory(share, path)
        for f in directory_listing:
            if f.is_directory():
                if f.get_longname() == '.' or f.get_longname() == '..' or f.get_longname() == 'Public' or f.get_longname() == 'Default' or f.get_longname() == 'Default User' or f.get_longname() == 'All Users':
                    continue
                
                directories = str(f.get_longname())
                aws_key = f'{path}\\{directories}\\.aws\\credentials'
                aws_base = f'C:{aws_key}'
                if smb_conn.file_exists(share, aws_key):
                    last_accessed = smb_conn.get_last_access_time(share, aws_key)
                    last_modified = smb_conn.get_last_write_time(share, aws_key)
                    cred_size = smb_conn.get_file_size(share, aws_key)
                    yield CloudCredentials('AWS', aws_base, last_accessed, last_modified, cred_size)

                for g_location in google_locations:
                    gcred_location = f'{path}\\{directories}\\{g_location}'
                    google_base = f'C:{gcred_location}'
                    if smb_conn.file_exists(share, gcred_location):
                        g_last_accessed = smb_conn.get_last_access_time(share, gcred_location)
                        g_last_modified = smb_conn.get_last_write_time(share, gcred_location)
                        g_cred_size = smb_conn.get_file_size(share, gcred_location)
                        yield CloudCredentials('Google', google_base, g_last_accessed, g_last_modified, g_cred_size)

                for a_location in azure_locations:
                    acred_location = f'{path}\\{directories}\\{a_location}'
                    azure_base = f'C:{acred_location}'
                    if smb_conn.file_exists(share, acred_location):
                        a_last_accessed = smb_conn.get_last_access_time(share, acred_location)
                        a_last_modified = smb_conn.get_last_write_time(share, acred_location)
                        a_cred_size = smb_conn.get_file_size(share, acred_location)
                        yield CloudCredentials('Azure', azure_base, a_last_accessed, a_last_modified, a_cred_size)

                for b_location in bluemix_locations:
                    bcred_location = f'{path}\\{directories}\\{b_location}'
                    bluemix_base = f'C:{bcred_location}'
                    if smb_conn.file_exists(share, bcred_location):
                        b_last_accessed = smb_conn.get_last_access_time(share, bcred_location)
                        b_last_modified = smb_conn.get_last_write_time(share, bcred_location)
                        b_cred_size = smb_conn.get_file_size(share, bcred_location)
                        yield CloudCredentials('Bluemix', bluemix_base, b_last_accessed, b_last_modified, b_cred_size)

def command_base(options):
    command = 'CloudCredentials'
    description = 'AWS/Google/Azure/Bluemix cloud credential files'
    command_group = ['user', 'remote']

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        smb_conn = SMBHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        for cc in get_cloud_credentials(smb_conn):
            if cc is not None:
                PrintHandler.print_props(cc)
    except KeyboardInterrupt:
        smb_conn.close()    
    except Exception as e:
        print(e)
        
    smb_conn.close()