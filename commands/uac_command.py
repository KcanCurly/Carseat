
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class UAC:
    def __init__(self, consentpromptbehavioradmin: int, enablelua: int, filteradministratortoken: int, localaccounttokenfilterpolicy: int):
        self.ConsentPromptBehaviorAdmin = consentpromptbehavioradmin
        self.EnableLua = enablelua
        self.FilterAdministratorToken = filteradministratortoken
        self.LocalAccountTokenFilterPolicy = localaccounttokenfilterpolicy

def get_uac(wmi_conn):
    content_prompt = wmi_conn.get_dword_value('HKLM', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'ConsentPromptBehaviorAdmin')
    enable_lua = wmi_conn.get_dword_value('HKLM', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' , 'EnableLUA')
    local_account_token_filter = wmi_conn.get_dword_value('HKLM', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'LocalAccountTokenFilterPolicy')
    filter_admin_token = wmi_conn.get_dword_value('HKLM', 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'FilterAdministratorToken')

    yield UAC(content_prompt, enable_lua, filter_admin_token, local_account_token_filter)

def format_results(uac):
    if uac.ConsentPromptBehaviorAdmin == 0:
        print(f"  {'ConsentPromptBehaviorAdmin':<30} : {uac.ConsentPromptBehaviorAdmin} - No prompting")
    elif uac.ConsentPromptBehaviorAdmin == 1:
        print(f"  {'ConsentPromptBehaviorAdmin':<30} : {uac.ConsentPromptBehaviorAdmin} - PromptOnSecureDesktop")
    elif uac.ConsentPromptBehaviorAdmin == 2:
        print(f"  {'ConsentPromptBehaviorAdmin':<30} : {uac.ConsentPromptBehaviorAdmin} - PromptPermitDenyOnSecureDesktop")
    elif uac.ConsentPromptBehaviorAdmin == 3:
        print(f"  {'ConsentPromptBehaviorAdmin':<30} : {uac.ConsentPromptBehaviorAdmin} - PromptForCredsNotOnSecureDesktop")
    elif uac.ConsentPromptBehaviorAdmin == 4:
        print(f"  {'ConsentPromptBehaviorAdmin':<30} : {uac.ConsentPromptBehaviorAdmin} - PromptForPermitDenyNotOnSecureDesktop")
    elif uac.ConsentPromptBehaviorAdmin == 5:
        print(f"  {'ConsentPromptBehaviorAdmin':<30} : {uac.ConsentPromptBehaviorAdmin} - PromptForNonWindowsBinaries")
    else:
        print(f"  {'ConsentPromptBehaviorAdmin':<30} : PromptForNonWindowsBinaries")

    enable_lua = uac.EnableLua == 1 or uac.EnableLua is None
    local_account_filter_policy_enabled = uac.LocalAccountTokenFilterPolicy == 1
    filter_administrator_token_enabled = uac.FilterAdministratorToken == 1

    print(f"  {'EnableLUA (Is UAC enabled?)':<30} : {uac.EnableLua}")
    print(f"  {'LocalAccountTokenFilterPolicy':<30} : {uac.LocalAccountTokenFilterPolicy}")
    print(f"  {'FilterAdministratorToken':<30} : {uac.FilterAdministratorToken}")

    if not enable_lua:
        print("    [*] UAC is disabled.\n    [*] Any administrative local account can be used for lateral movement.")
    if enable_lua and not local_account_filter_policy_enabled and not filter_administrator_token_enabled:
        print("    [*] Default Windows settings - Only the RID-500 local admin account can be used for lateral movement.")
    if enable_lua and local_account_filter_policy_enabled:
        print("    [*] LocalAccountTokenFilterPolicy == 1. Any administrative local account can be used for lateral movement.")
    if enable_lua and not local_account_filter_policy_enabled and filter_administrator_token_enabled:
        print("    [*] LocalAccountTokenFilterPolicy set to 0 and FilterAdministratorToken == 1.\n    [*] Local accounts cannot be used for lateral movement.")

def command_base(options):
    command = 'UAC'
    description = 'UAC system policies via the registry'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"
    
    domain, username, password, address = parse_target(options.target)
    
    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for uac in get_uac(wmi_conn):
            if uac is not None:
                format_results(uac)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()