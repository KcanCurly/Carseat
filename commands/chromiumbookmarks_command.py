
import json
from lib import SMBHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class ChromiumBookmark:
    def __init__(self, username: str, filepath: str, bookmarks: list):
        self.UserName = username
        self.FilePath = filepath
        self.Bookmarks = bookmarks

class Bookmark:
    def __init__(self, name: str, url: str):
        self.Name = name
        self.Url = url

def parse_bookmarks(contents):
    bmark = []
    try:
        deserialized = json.loads(contents)
        roots = deserialized["roots"]
        bookmark_bar = roots["bookmark_bar"]
        children = bookmark_bar["children"]

        for entry in children:
            bookmark = Bookmark(name=entry["name"].strip(), url=entry.get("url", "(Bookmark Folder?)"))
            bmark.append(bookmark)

    except json.JSONDecodeError:
        print("[-] File is not a valid JSON")
    except KeyError as e:
        print(f"[-] Expected key not found in JSON structure: {e}")
    except Exception as e:
        print(f"[-] Error processing bookmarks: {str(e)}")

    return bmark

def get_chromium_bookmarks(smb_conn):
    share = "C$"
    user_path = "\\Users" 
    path_list = [
        "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\",
        "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\",
        "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\",
        "\\AppData\\Roaming\\Opera Software\\Opera Stable\\"
    ]
    bookmarks = []
    fix_path = ''
    if smb_conn.connect():
        directory_listing = smb_conn.list_directory(share, user_path)
        for f in directory_listing:
            if f.is_directory():
                if f.get_longname() == '.' or f.get_longname() == '..' or f.get_longname() == 'Public' or f.get_longname() == 'Default' or f.get_longname() == 'Default User' or f.get_longname() == 'All Users':
                    continue
                user = str(f.get_longname())
                for path in path_list:
                    ch_bm_path = f'{user_path}\\{user}{path}'
                    bm = f'{ch_bm_path}\\Bookmarks'
                    if smb_conn.file_exists(share, bm):
                        fix_path = f'C:{ch_bm_path}'
                        try:
                            json_data = smb_conn.show_file_content(share, ch_bm_path, 'Bookmarks')
                            bookmarks = parse_bookmarks(json_data)
                        except Exception as e:
                            continue
                yield ChromiumBookmark(user, fix_path, bookmarks)

def format_results(bookmark):
    if len(bookmark.Bookmarks) > 0:
        print(f'Bookmarks ({bookmark.FilePath})\n')

        for b in bookmark.Bookmarks:
            print(f"    Name : {b.Name}")
            print(f"    URL  : {b.Url}\n")

def command_base(options):
    command = 'ChromiumBookmarks'
    description = 'Parses any found Chrome/Edge/Brave/Opera bookmark files'
    command_group = ['user', 'chromium', 'remote']

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        smb_conn = SMBHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        for bookmark in get_chromium_bookmarks(smb_conn):
            if bookmark is not None:
                format_results(bookmark)
                print()
    except KeyboardInterrupt:
        smb_conn.close()    
    except Exception as e:
        print(e)

    smb_conn.close()