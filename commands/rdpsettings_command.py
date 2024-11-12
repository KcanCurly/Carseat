
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class ClientSettings:
    def __init__(self, restrictedadmin: bool, restrictedadmintype: int, serverauthlevel: int, disablepasswordsaving: bool):
        self.RestrictedRemoteAdministration = restrictedadmin
        self.RestrictedRemoteAdministrationType = restrictedadmintype
        self.ServerAuthLevel = serverauthlevel
        self.DisablePasswordSaving = disablepasswordsaving

class ServerSettings:
    def __init__(self, nla: int, blockclipboardredirection: int, blockcomportredirection: int, blockdriveredirection: int, blocklptportredirection: int, allowsmartcardredirection: int, blockpnpdeviceredirection: int, blockprinterredirection: int):
        self.NetworkLevelAuthentication = nla
        self.BlockClipboardRedirection = blockclipboardredirection
        self.BlockComPortRedirection = blockcomportredirection
        self.BlockDriveRedirection = blockdriveredirection
        self.BlockLptPortRedirection = blocklptportredirection
        self.AllowSmartCardRedirection = allowsmartcardredirection
        self.BlockPnPDeviceRedirection = blockpnpdeviceredirection
        self.BlockPrinterRedirection = blockprinterredirection

class RDPSettings:
    def __init__(self, clientsettings: ClientSettings, serversettings: ServerSettings):
        self.ClientSettings = clientsettings
        self.ServerSettings = serversettings

def get_rdp_settings(wmi_conn):
    #client settings
    restricted_admin = wmi_conn.get_dword_value('HKLM', 'Software\\Policies\\Microsoft\\Windows\\CredentialsDelegation', 'RestrictedRemoteAdministration')
    restricted_admin_type = wmi_conn.get_dword_value('HKLM', 'Software\\Policies\\Microsoft\\Windows\\CredentialsDelegation', 'RestrictedRemoteAdministrationType')
    server_auth_level = wmi_conn.get_dword_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services', 'AuthenticationLevel')
    disable_pw_saving = wmi_conn.get_dword_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services', 'DisablePasswordSaving')

    #server settings
    nla = wmi_conn.get_dword_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services', 'UserAuthentication')
    block_clipboard = wmi_conn.get_dword_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services', 'fDisableClip')
    block_com_port = wmi_conn.get_dword_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services', 'fDisableCcm')
    block_drives = wmi_conn.get_dword_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services', 'fDisableCdm')
    block_lpt_port = wmi_conn.get_dword_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services', 'fDisableLPT')
    block_smart_card = wmi_conn.get_dword_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services', 'fEnableSmartCard')
    block_pnp = wmi_conn.get_dword_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services', 'fDisablePNPRedir')
    block_printers = wmi_conn.get_dword_value('HKLM', 'SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services', 'fDisableCpm')

    yield RDPSettings(
        ClientSettings(restricted_admin != None and restricted_admin != 0, restricted_admin_type, server_auth_level, disable_pw_saving != None or disable_pw_saving != 0 ),
        ServerSettings(nla, block_clipboard, block_com_port, block_drives, block_lpt_port, block_smart_card, block_pnp, block_printers))

def format_results(rdpsettings):
    server = rdpsettings.ServerSettings
    client = rdpsettings.ClientSettings

    print('RDP Server Settings:')
    print(f"  NetworkLevelAuthentication: {server.NetworkLevelAuthentication}")
    print(f"  BlockClipboardRedirection:  {server.BlockClipboardRedirection}")
    print(f"  BlockComPortRedirection:    {server.BlockComPortRedirection}")
    print(f"  BlockDriveRedirection:      {server.BlockDriveRedirection}")
    print(f"  BlockLptPortRedirection:    {server.BlockLptPortRedirection}")
    print(f"  BlockPnPDeviceRedirection:  {server.BlockPnPDeviceRedirection}")
    print(f"  BlockPrinterRedirection:    {server.BlockPrinterRedirection}")
    print(f"  AllowSmartCardRedirection:  {server.AllowSmartCardRedirection}")

    print('\nRDP Client Settings:')
    print(f"  DisablePasswordSaving: {client.DisablePasswordSaving}")
    print(f"  RestrictedRemoteAdministration: {client.RestrictedRemoteAdministration}")

    rra_type = rdpsettings.ClientSettings.RestrictedRemoteAdministrationType

    if rra_type:
        if rra_type == 1:
            t = 'Require Restricted Admin Mode'
        elif rra_type == 2:
            t = 'Require Remote Credential Guard'
        elif rra_type == 3:
            t = 'Require Restricted Admin or Remote Credential Guard'
        else:
            t = f'{rra_type} - Unknown, please report this'
        print(f'  RestrictedRemoteAdministrationType: {t}')

    level = rdpsettings.ClientSettings.ServerAuthLevel

    if level:
        if level == 1:
            l = 'Require Restricted Admin Mode'
        elif level == 2:
            l = 'Require Remote Credential Guard'
        elif level == 3:
            l = 'Require Restricted Admin or Remote Credential Guard'
        else:
            l = f'{level} - Unknown, please report this'
        print(f'  RestrictedRemoteAdministrationType: {l}')


def command_base(options):
    command = 'RDPsettings'
    description = 'Remote Desktop Server/Client Settings'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"
    
    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for rdp_settings in get_rdp_settings(wmi_conn):
            if rdp_settings is not None:
                format_results(rdp_settings)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()