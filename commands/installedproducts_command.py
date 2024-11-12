
from datetime import datetime
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class InstalledProducts:
    def __init__(self, displayname: str, displayversion: str, publisher: str, installdate: str, architecture: str):
        self.DisplayName = displayname
        self.DisplayVersion = displayversion
        self.Publisher = publisher
        self.InstallDate = installdate
        self.Architecture = architecture

def get_installed_products(wmi_conn):
    product_keys = [
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    ]

    for prod in product_keys:
        arch = 'x86'
        if prod == 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall':
            arch = 'x64'

        sub_key_names = wmi_conn.get_subkey_names('HKLM', prod)
        for sub_key in sub_key_names:
            display_name = wmi_conn.get_string_value('HKLM', f'{prod}\\{sub_key}', 'DisplayName')
            display_version = wmi_conn.get_string_value('HKLM', f'{prod}\\{sub_key}', 'DisplayVersion')
            publisher = wmi_conn.get_string_value('HKLM', f'{prod}\\{sub_key}', 'Publisher')
            install_date_str = wmi_conn.get_string_value('HKLM', f'{prod}\\{sub_key}', 'InstallDate')
            install_date = datetime.min
            if install_date_str and install_date_str.strip():
                try:
                    year = install_date_str[0:4]
                    month = install_date_str[4:6]
                    day = install_date_str[6:8]
                    date = f"{year}-{month}-{day}"
                    install_date = datetime.strptime(date, "%Y-%m-%d")
                except:
                    pass
            if display_name is not None:
                yield InstalledProducts(display_name, display_version, publisher, install_date, arch)


def command_base(options):
    command = 'InstalledProducts'
    description = 'Installed products via the registry'
    command_group = ['misc', 'remote']
    wmi_namespace = "//./root/CIMv2"

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for product in get_installed_products(wmi_conn):
            if product is not None:
                PrintHandler.print_props(product)
                print()
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()