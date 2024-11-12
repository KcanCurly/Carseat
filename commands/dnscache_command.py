
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class DNSCache:
    def __init__(self, entry: str, name :str, data: str):
        self.Entry = entry
        self.Name = name
        self.Data = data

def get_dns_cache(wmi_conn):
    try:
        dns_data = wmi_conn.wmi_get('SELECT * FROM MSFT_DNSClientCache')
    except Exception as e:
        print("  [X] 'MSFT_DNSClientCache' WMI class unavailable (minimum supported versions of Windows: 8/2012)")
        return None
        
    for d in dns_data:
        data = wmi_conn.parse_wmi(d)
        yield DNSCache(data['Entry'], data['Name'], data['Data'])

def command_base(options):
    command = 'DNSCache'
    description = 'DNS Cache Entries'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/StandardCIMv2"
    
    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for cache in get_dns_cache(wmi_conn):
            if cache is not None:
                PrintHandler.print_props(cache)
                print()
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()