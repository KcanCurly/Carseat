
import struct
from datetime import datetime, timedelta, date, timezone
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target


class IEUrls:
    def __init__(self, sid: str, urls: list):
        self.Sid = sid
        self.Urls = urls

class TypedURL:
    def __init__(self, time: str, url: str):
        self.Time = time
        self.Url = url

def from_file_time(file_time):
    windows_epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    delta = datetime(1970, 1, 1, tzinfo=timezone.utc) - windows_epoch
    unix_epoch_offset = int(delta.total_seconds() * 1e7)
    microseconds = (file_time - unix_epoch_offset) // 10
    return (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=microseconds)).date()

def get_ie_urls(wmi_conn, args):
    days = 7
    if len(args) >= 1:
        try:
            days = int(args[0])
        except (TypeError, ValueError):
            print('ERROR: Argument is not an integer')
            return
    start_time = date.today() - timedelta(days=days)
    print(f'Internet Explorer typed URLs for the last {days} days\n')
    try:
        sids = wmi_conn.get_subkey_names('HKU', '')
        for sid in sids:
            if not sid.startswith('S-1-5') or sid.endswith('_Classes'):
                continue
            settings = wmi_conn.get_registry_value('HKU', f'{sid}\\SOFTWARE\\Microsoft\\Internet Explorer\\TypedURLs')
            if settings is None or len(settings) <= 1:
                continue
            urls = []
            for k, v in settings.items():
                time_bytes = wmi_conn.get_binary_value('HKU', f'{sid}\\SOFTWARE\\Microsoft\\Internet Explorer\\TypedURLsTime', k)
                if time_bytes is None:
                    continue
                time_long = struct.unpack('<Q', time_bytes)[0]
                url_time = from_file_time(time_long)
                if url_time > start_time:
                    urls.append(TypedURL(url_time, v.strip()))
            yield IEUrls(sid, urls)
    except Exception as e:
        print(e)

def format_results(ie):
    print(f'\n {ie.Sid}')

    for url in ie.Urls:
        print(f'    {str(url.Time):<23} :  {url.Url}')

    print()

def command_base(options):
    command = 'IEUrls'
    description = 'Internet Explorer typed URLs (last 7 days, argument == last X days)'
    command_group = ['user', 'remote']
    wmi_namespace = "//./root/CIMv2"

    args = ''
    if options.command_args:
        module_args = options.command_args[command.lower()]
        if module_args:
            args = module_args.split()

    domain, username, password, address = parse_target(options.target)
        
    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for ieurls in get_ie_urls(wmi_conn, args):
            if ieurls is not None:
                format_results(ieurls)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()