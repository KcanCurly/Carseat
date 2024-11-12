
from lib import SMBHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class OutlookDownloads:
    def __init__(self, folder: str, downloads: list):
        self.Folder = folder
        self.Downloads = downloads

class OutlookDownload:
    def __init__(self, filename: str, lastaccessed: str, lastmodified: str):
        self.FileName = filename
        self.LastAccessed = lastaccessed
        self.LastModified = lastmodified

def get_outlook_downloads(smb_conn):
    share = "C$"
    path = "\\Users" 

    if smb_conn.connect():
        directory_listing = smb_conn.list_directory(share, path)
        for f in directory_listing:
            if f.is_directory():
                if f.get_longname() == '.' or f.get_longname() == '..' or f.get_longname() == 'Public' or f.get_longname() == 'Default' or f.get_longname() == 'Default User' or f.get_longname() == 'All Users':
                    continue

            user = str(f.get_longname())
            outlook_base = f'{path}\\{user}\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\'
            if not smb_conn.file_exists(share, outlook_base):
                continue
            directories = smb_conn.list_directory(share, outlook_base)
            for dir in directories:
                if dir.is_directory():
                    if dir.get_longname() == '.' or dir.get_longname() == '..':
                        continue

                    dl_location = f'{outlook_base}{dir.get_longname()}'
                    files = smb_conn.list_directory(share, dl_location)
                    downloads = []
                    for f in files:
                        if not f.is_directory():
                            fn = f.get_longname()
                            fix_dir = f'C:{dl_location}'
                            la = smb_conn.get_last_access_time(share, f'{dl_location}\\{fn}')
                            down = OutlookDownload(fn, la ,la)
                            downloads.append(down)
                            
                    yield OutlookDownloads(fix_dir, downloads)

def format_results(downloads):
    print(f"  Folder : {downloads.Folder}\n")
    print('    LastAccessed              LastModified              FileName')
    print('    ------------              ------------              --------')
    for d in downloads.Downloads:
        print(f"    {d.LastAccessed:<22}    {d.LastModified:<22}    {d.FileName}")

def command_base(options):
    command = 'OutlookDownloads'
    description = 'List files downloaded by Outlook'
    command_group = ['misc', 'remote']

    domain, username, password, address = parse_target(options.target)
    
    PrintHandler.show_banner(command)
    try:
        smb_conn = SMBHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        for od in get_outlook_downloads(smb_conn):
            if od is not None:
                format_results(od)
                print()
    except KeyboardInterrupt:
        smb_conn.close()
    except Exception as e:
        print(e)

    smb_conn.close()