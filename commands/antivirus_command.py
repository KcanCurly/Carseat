
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class AntiVirus:
    def __init__(self, engine: str, productexe: str, reportingexe: str):
        self.Engine = engine
        self.ProductEXE = productexe
        self.ReportingEXE = reportingexe

def get_av(wmi_conn):
    try:
        av_info = wmi_conn.wmi_get('SELECT * from AntiVirusProduct')
    except Exception as e:
        print(' [X] Cannot enumerate antivirus. root\\SecurityCenter2 WMI namespace is not available on Windows Servers')
        return None

    for av in av_info:
        data = wmi_conn.parse_wmi(av)
        yield AntiVirus(data['displayName'], data['pathToSignedProductExe'], data['pathToSignedReportingExe'])

def command_base(options):
    command = 'AntiVirus'
    description = 'Registered antivirus'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/SecurityCenter2"
    
    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for avs in get_av(wmi_conn):
            if avs is not None:
                PrintHandler.print_props(avs)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()
