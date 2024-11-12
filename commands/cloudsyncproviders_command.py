
from datetime import datetime
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class OneDriveSyncProvider:
    def __init__(self):
        self.mpList = {}
        self.OneDriveList = {}
        self.AcctoMPMapping = {}
        self.useScopeIDs = []

class CloudSyncProviders:
    def __init__(self, sid: str, odsp: OneDriveSyncProvider):
        self.Sid = sid
        self.Odsp = odsp

def get_cloud_sync_providers(wmi_conn):
    sids = wmi_conn.get_user_sids()
    for sid in sids:
        if not sid.startswith('S-1-5') or sid.endswith('_Classes'):
            continue
        
        o = OneDriveSyncProvider()

        subkeys = wmi_conn.get_subkey_names('HKU', f'{sid}\\Software\\SyncEngines\\Providers\\OneDrive')
        if subkeys is None:
            continue
        
        for rname in subkeys:
            provider = {}
            for x in ["LibraryType", "LastModifiedTime", "MountPoint", "UrlNamespace"]:
                result = wmi_conn.get_string_value('HKU', f'{sid}\\Software\\SyncEngines\\Providers\\OneDrive\\{rname}', x)
                if result:
                    provider[x] = result
            o.mpList[rname] = provider

        od_account = wmi_conn.get_subkey_names('HKU', f'{sid}\\Software\\Microsoft\\OneDrive\\Accounts')
        if od_account is None:
            continue
        for acc in od_account:
            business = False
            account = {}
            for x in ["DisplayName", "Business", "ServiceEndpointUri", "SPOResourceId", "UserEmail", "UserFolder", "UserName", "WebServiceUrl"]:
                result = wmi_conn.get_string_value('HKU', f'{sid}\\Software\\Microsoft\\OneDrive\\Accounts\\{acc}', x)
                if result:
                    account[x] = result
                if x == 'Business':
                    business = result == "1"
            od_mount_points = wmi_conn.get_registry_value('HKU', f'{sid}\\Software\\Microsoft\\OneDrive\\Accounts\\{acc}\\ScopeIdToMountPointPathCache')
            scope_ids = []
            if business == True:
                for mp_key, mp_val in od_mount_points.items():
                    scope_ids.append(mp_key)
            else:
                scope_ids.append(acc)
            o.AcctoMPMapping[acc] = scope_ids
            o.OneDriveList[acc] = account
            o.useScopeIDs.extend(scope_ids)

        yield CloudSyncProviders(sid, o)

def format_results(provider):
    print(f'  {provider.Sid} :')

    for item_key, item_val in provider.Odsp.OneDriveList.items():
        if len(item_val) == 0:
            continue
        
        accName = item_key
        print(f'\r\n    {accName} :')

        for sub_key, sub_val in item_val.items():
            print(f'      {sub_key} : {sub_val}')

        for mp in provider.Odsp.AcctoMPMapping[accName]:
            print()

            if mp not in provider.Odsp.mpList:
                continue
            for mp_key, mp_val in provider.Odsp.mpList[mp].items():
                if mp_key == 'LastModifiedTime':
                    parsed_date = datetime.strptime(mp_val, "%Y-%m-%d %H:%M:%S")
                    formatted_date = parsed_date.strftime("%a %d %b %Y %H:%M:%S")
                    print(f"      | {mp_key} : {mp_val} ({formatted_date})")
                else:
                    print(f"      | {mp_key} : {mp_val}") 

    all_scope_ids = list(provider.Odsp.mpList.keys())
    print('\r\n    Orphaned :')
    for scope_id in all_scope_ids:
        if scope_id in provider.Odsp.useScopeIDs:
            for key, value in provider.Odsp.mpList[scope_id].items():
                if key == 'LastModifiedTime':
                    parsed_date = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
                    formatted_date = parsed_date.strftime("%a %d %b %Y %H:%M:%S")
                    print(f"      | {key} : {value} ({formatted_date})")
                else:
                    print(f"      | {key} : {value}") 
            print()
    print()

def command_base(options):
    command = 'CloudSyncProviders'
    description = 'All configured Office 365 endpoints (tenants and teamsites) which are synchronised by OneDrive.'
    command_group = ['user', 'remote']
    wmi_namespace = "//./root/CIMv2"
    
    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for res in get_cloud_sync_providers(wmi_conn):
            if res is not None:
                format_results(res)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()
    