
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class AutoRuns:
    def __init__(self, key: str, entries: list):
        self.Key = key
        self.Entries = entries

def get_auto_runs(wmi_obj):
    autorun_locs = [
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunService",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceService",
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunService",
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceService"
    ]
    for i in autorun_locs:
        settings = wmi_obj.get_registry_value('HKLM', i)
        if settings and len(settings) != 0:
            full_reg_key = f"HKLM:{i}"
            autoruns = list(settings.values())
            yield AutoRuns(full_reg_key, autoruns)
   

def command_base(options):
    command = 'Autoruns'
    description = 'Auto run executables/scripts/programs'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"
    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for autoruns in get_auto_runs(wmi_conn):
            if autoruns is not None:
                PrintHandler.print_key_entries(autoruns)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()