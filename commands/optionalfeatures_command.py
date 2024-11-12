
from enum import IntEnum
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class OptionalFeatureState(IntEnum):
    Enabled = 1
    Disabled = 2
    Absent = 3
    Unknown = 4

class OptionalFeatures:
    def __init__(self, name: str, caption: str, state: str):
        self.Name = name
        self.Caption = caption
        self.State = state

def get_optional_features(wmi_conn):
    results = []
    wmi_data = wmi_conn.wmi_get('SELECT Name,Caption,InstallState FROM Win32_OptionalFeature')
    for d in wmi_data:
        data = wmi_conn.parse_wmi(d)
        state = OptionalFeatureState(data['InstallState']).name
        if data['InstallState'] != OptionalFeatureState.Enabled:
           continue

        feature = OptionalFeatures(data['Name'], data['Caption'], state)
        results.append(feature)
    for r in sorted(results, key=lambda x: x.Name):
        yield r

def format_results(features):
    print(f"{features.State:<8} {features.Name:<50} {features.Caption}")

def command_base(options):
    command = 'OptionalFeatures'
    description = 'List Optional Features/Roles (via WMI)'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        print(f"{'State':<8} {'Name':<50} {'Caption'}")
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for features in get_optional_features(wmi_conn):
            if features is not None:
                format_results(features)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()