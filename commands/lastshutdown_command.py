
import struct
from datetime import datetime, timezone, timedelta
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class LastShutdown:
    def __init__(self, lastshutdown: str):
        self.LastShutDown = lastshutdown

def get_lastshutdown(wmi_conn):
    shutdown_bytes = wmi_conn.get_binary_value('HKLM', 'SYSTEM\\ControlSet001\\Control\\Windows', 'ShutdownTime')
    if shutdown_bytes is not None:
        shutdown_int = struct.unpack('<Q', shutdown_bytes)[0]
        WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
        WINDOWS_TICKS = int(shutdown_int)
        delta = WINDOWS_TICKS / 10_000_000
        shutdown_time = WINDOWS_EPOCH + timedelta(seconds=delta)
        local_time = shutdown_time.astimezone()
        formatted_time = local_time.strftime("%m/%d/%Y %I:%M:%S %p")
        yield LastShutdown(formatted_time)

def command_base(options):
    command = 'LastShutdown'
    description = 'Returns the DateTime of the last system shutdown (via the registry).'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for shutdown in get_lastshutdown(wmi_conn):
            if shutdown is not None:
                PrintHandler.print_props(shutdown)
                print()
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)
        
    wmi_conn.close()