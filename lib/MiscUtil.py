import re

class MiscUtil:
    def __init__(self):
        pass
    
    @staticmethod
    def get_process_cmdline_regex():
        process_cmdline_regex = [
            # re.compile(r"(New-Object.*System.Management.Automation.PSCredential.*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(ConvertTo-SecureString.*AsPlainText.*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(net(.exe)?.*user .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(net(.exe)?.*use .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(cmdkey(.exe)?.*/pass:.*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(ssh(.exe)?.*-i .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(psexec(.exe)?.*-p .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(psexec64(.exe)?.*-p .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(winrm(.vbs)?.*-p .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(winrs(.exe)?.*/p(assword)? .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(putty(.exe)?.*-pw .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(pscp(.exe)?.*-pw .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(kitty(.exe)?.*(-pw|-pass) .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(bitsadmin(.exe)?.*(/RemoveCredentials|/SetCredentials) .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(bootcfg(.exe)?.*/p .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(certreq(.exe)?.*-p .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(certutil(.exe)?.*-p .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(driverquery(.exe)?.*/p .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(eventcreate(.exe)?.*/p .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(getmac(.exe)?.*/p .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(gpfixup(.exe)?.*/pwd:.*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(gpresult(.exe)?.*/p .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(mapadmin(.exe)?.*-p .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(mount(.exe)?.*-p:.*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(nfsadmin(.exe)?.*-p .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(openfiles(.exe)?.*/p .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(cscript.*-w .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(schtasks(.exe)?.*(/p|/rp) .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(setx(.exe)?.*/p .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(systeminfo(.exe)?.*/p .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(takeown(.exe)?.*/p .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(taskkill(.exe)?.*/p .*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(tscon(.exe)?.*/password:.*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(wecutil(.exe)?.*(/up|/cup|/p):.*)", re.IGNORECASE | re.MULTILINE),
            re.compile(r"(wmic(.exe)?.*/password:.*)", re.IGNORECASE | re.MULTILINE)
        ]
        
        return process_cmdline_regex
    
    @staticmethod
    def parse_sddl(sddl_string):
        access_list = []
        
        # Regular expression to match ACE entries in SDDL
        ace_pattern = r'(A|D);([^;]+);([^;]+);([^;]+);([^;]+);([^;(\r\n)]+)'
        matches = re.finditer(ace_pattern, sddl_string)
        
        for match in matches:
            ace_type, flags, rights, object_guid, inherit_object_guid, sid = match.groups()
            access_str = "Allow" if ace_type == "A" else "Deny"
            sid_mapping = {
                "BA": "BUILTIN\\Administrators",
                "SY": "NT AUTHORITY\\SYSTEM",
                "WD": "Everyone",
                "BU": "BUILTIN\\Users",
                "AU": "Authenticated Users",
                "AN": "Anonymous",
                "NO": "Network Configuration Operators",
                "IU": "Interactive Users",
                "LA": "Local Administrator"
            }
            principal = sid_mapping.get(sid, sid)
            
            access_list.append(PluginAccess(
                principal=principal,
                security_identifier=sid,
                access_str=access_str
            ))
        
        return access_list