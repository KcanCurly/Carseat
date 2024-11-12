
from datetime import datetime
from enum import IntEnum
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class NetworkCategory(IntEnum):
    PUBLIC = 0
    HOME = 1
    WORK = 2

class NetworkType(IntEnum):
    WIRED = 6
    VPN = 23
    WIRELESS = 25
    MOBILE_BROADBAND = 243

class NetworkProfiles:
    def __init__(self, profilename: str, description: str, networkcategory: str, networktype: str, managed: str, datecreated: str, datelastconnected: str):
        self.ProfileName = profilename
        self.Description = description
        self.NetworkCategory = networkcategory
        self.NetworkType = networktype
        self.Managed = managed
        self.DateCreated = datecreated
        self.DateLastConnected = datelastconnected

def convert_binary_datetime(bytes_data):
    if bytes_data is None or len(bytes_data) == 0:
        return datetime.min.strftime("%m/%d/%Y %I:%M:%S %p")
    
    year = int(f"{bytes_data[1]:02X}{bytes_data[0]:02X}", 16)
    month = int(f"{bytes_data[3]:02X}{bytes_data[2]:02X}", 16)
    weekday = int(f"{bytes_data[5]:02X}{bytes_data[4]:02X}", 16)
    day = int(f"{bytes_data[7]:02X}{bytes_data[6]:02X}", 16)
    hour = int(f"{bytes_data[9]:02X}{bytes_data[8]:02X}", 16)
    minute = int(f"{bytes_data[11]:02X}{bytes_data[10]:02X}", 16)
    second = int(f"{bytes_data[13]:02X}{bytes_data[12]:02X}", 16)
    
    dt = datetime(year, month, day, hour, minute, second)
    return dt.strftime("%m/%d/%Y %I:%M:%S %p")


def get_network_profiles(wmi_conn):
    profile_guids = wmi_conn.get_subkey_names('HKLM', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\')
    for pguid in profile_guids:
        profile_name = wmi_conn.get_string_value('HKLM', f'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\{pguid}', 'ProfileName')
        description = wmi_conn.get_string_value('HKLM', f'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\{pguid}', 'Description')
        networkcategory = wmi_conn.get_dword_value('HKLM', f'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\{pguid}', 'Category')
        network_category = NetworkCategory(int(networkcategory)).name
        networktype = wmi_conn.get_dword_value('HKLM', f'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\{pguid}', 'NameType')
        network_type = NetworkType(int(networktype)).name
        managed = wmi_conn.get_dword_value('HKLM', f'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\{pguid}', 'Managed')
        date_created_bytes = wmi_conn.get_binary_value('HKLM', f'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\{pguid}', 'DateCreated')
        date_created = convert_binary_datetime(date_created_bytes)
        date_connected_bytes = wmi_conn.get_binary_value('HKLM', f'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\{pguid}', 'DateCreated')
        date_lastconnected = convert_binary_datetime(date_connected_bytes)

        yield NetworkProfiles(profile_name, description, network_category, network_type, managed, date_created, date_lastconnected)

def command_base(options):
    command = 'NetworkProfiles'
    description = 'Windows network profiles'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for profiles in get_network_profiles(wmi_conn):
            if profiles is not None:
                PrintHandler.print_props(profiles)
                print()
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()