
import sys
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class AMSIProviders:
    def __init__(self, guid: str, providerpath: str):
        self.GUID = guid
        self.ProviderPath = providerpath

def get_amsi_providers(wmi_data):
    try:
        provider_clsids = wmi_data.get_subkey_names('HKLM', 'SOFTWARE\\Microsoft\\AMSI\\Providers')
    except:
        return None
    
    for provider_clsid in provider_clsids:
        provider_path_key = f"SOFTWARE\\Classes\\CLSID\\{provider_clsid}\\InprocServer32"
        try:
            provider_path = wmi_data.get_string_value('HKLM', provider_path_key, "")
        except:
            provider_path = ""

        yield AMSIProviders(provider_clsid, provider_path)

def command_base(options):
    command = 'AMSIProviders'
    description = 'Providers registered for AMSI'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for providers in get_amsi_providers(wmi_conn):
            if providers is not None:
                PrintHandler.print_props(providers)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)
    wmi_conn.close()