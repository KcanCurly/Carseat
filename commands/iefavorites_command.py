
from lib import SMBHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class IEFavorites:
    def __init__(self, username: str, favorites: list):
        self.UserName = username
        self.Favorites = favorites

def get_ie_favorites(smb_conn):
    share = "C$"
    path = "\\Users"  

    directory_listing = smb_conn.list_directory(share, path)
    for f in directory_listing:
        if f.is_directory():
            if f.get_longname() == '.' or f.get_longname() == '..' or f.get_longname() == 'Public' or f.get_longname() == 'Default' or f.get_longname() == 'Default User' or f.get_longname() == 'All Users':
                continue

            username = f.get_longname()
            favorites_base = f'{path}\\{username}\\Favorites\\'
            c_fav = []
            urls = smb_conn.list_directory(share, favorites_base)
            favorites = []
            for u in urls:
                if u.get_longname().endswith('.url'):
                    rdr = smb_conn.show_file_content(share, favorites_base, u.get_longname())
                    for line in rdr.splitlines():
                        if not line.startswith('URL='):
                            continue
                        if len(line) > 4:
                            url = line[4:]
                            favorites.append(url.strip(' '))
            yield IEFavorites(username, favorites)

            
def format_results(iefav):
    print(f'\nFavorites ({iefav.UserName})\n')

    for f in iefav.Favorites:
        print(f'  {f}')

def command_base(options):
    command = 'IEFavorites'
    description = 'Internet Explorer favorites'
    command_group = ['user', 'remote']

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        smb_conn = SMBHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        for favorites in get_ie_favorites(smb_conn):
            if favorites is not None:
                format_results(favorites)
    except KeyboardInterrupt:
        smb_conn.close()
    except Exception as e:
        print(e)

    smb_conn.close()


