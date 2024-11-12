from impacket.dcerpc.v5 import transport, samr, lsad, lsat, wkst, srvs
from impacket.smbconnection import SMBConnection
from datetime import datetime
from typing import Optional, List, Dict, Any

class SAMRHandler:
    def __init__(self, target: str, username: str = '', password: str = '', domain: str = '', hashes: str = None, aesKey: str = None, doKerberos: bool = False, kdcHost: str = None):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.port = 445
        self.lmhash = ''
        self.nthash = ''
        self.aesKey = aesKey
        self.doKerberos = doKerberos
        self.kdcHost = kdcHost
        self._smb_conn = None
        self._samr_dce = None
        self._lsat_dce = None
        self._server_handle = None
        self._domain_handle = None
        if hashes is not None:
            self.lmhash, self.nthash = hashes.split(':')

    def connect(self):
        if not self._smb_conn:
            self._smb_conn = SMBConnection(self.target, self.target, sess_port=self.port)
            
            if self.doKerberos:
                self._smb_conn.kerberosLogin(self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey, self.kdcHost)
            else:
                self._smb_conn.login(self.username, self.password, self.domain, self.lmhash, self.nthash)

            samr_rpc = transport.DCERPCTransportFactory(f'ncacn_np:{self.target}[\\pipe\\samr]')
            samr_rpc.set_smb_connection(self._smb_conn)
            self._samr_dce = samr_rpc.get_dce_rpc()
            self._samr_dce.connect()
            self._samr_dce.bind(samr.MSRPC_UUID_SAMR)

            lsat_rpc = transport.DCERPCTransportFactory(f'ncacn_np:{self.target}[\\pipe\\lsarpc]')
            lsat_rpc.set_smb_connection(self._smb_conn)
            self._lsat_dce = lsat_rpc.get_dce_rpc()
            self._lsat_dce.connect()
            self._lsat_dce.bind(lsat.MSRPC_UUID_LSAT)

    def disconnect(self):
        if self._domain_handle:
            samr.hSamrCloseHandle(self._samr_dce, self._domain_handle)
            self._domain_handle = None
            
        if self._server_handle:
            samr.hSamrCloseHandle(self._samr_dce, self._server_handle)
            self._server_handle = None
            
        if self._samr_dce:
            self._samr_dce.disconnect()
            self._samr_dce = None
            
        if self._lsat_dce:
            self._lsat_dce.disconnect()
            self._lsat_dce = None
            
        if self._smb_conn:
            self._smb_conn.close()
            self._smb_conn = None

    def _get_domain_handle(self, builtin: bool = False) -> bytes:
        if not self._server_handle:
            self._server_handle = samr.hSamrConnect(self._samr_dce)['ServerHandle']

        domain_name = samr.hSamrEnumerateDomainsInSamServer(
            self._samr_dce, 
            self._server_handle
        )['Buffer']['Buffer'][1 if builtin else 0]['Name']

        domain_sid = samr.hSamrLookupDomainInSamServer(
            self._samr_dce, 
            self._server_handle, 
            domain_name
        )['DomainId']

        domain_handle = samr.hSamrOpenDomain(
            self._samr_dce, 
            self._server_handle, 
            domainId=domain_sid
        )['DomainHandle']
        
        return domain_handle

    def get_local_group_members(self, group_name: str):
        try:
            domain_handle = self._get_domain_handle(builtin=True)
            group_rid = samr.hSamrLookupNamesInDomain(self._samr_dce, domain_handle, (group_name,))['RelativeIds']['Element'][0]['Data']
            alias_handle = samr.hSamrOpenAlias(self._samr_dce, domain_handle, samr.MAXIMUM_ALLOWED, group_rid)['AliasHandle']

            members = samr.hSamrGetMembersInAlias(self._samr_dce, alias_handle)
            policy_handle = lsad.hLsarOpenPolicy2(self._lsat_dce)['PolicyHandle']
            sids = [member['Data']['SidPointer'].formatCanonical() for member in members['Members']['Sids']]
            names = lsat.hLsarLookupSids2(self._lsat_dce, policy_handle, sids)
            
            results = []
            domains = names['ReferencedDomains']['Domains']
            for i, name in enumerate(names['TranslatedNames']['Names']):
                domain_index = name['DomainIndex']
                domain = domains[domain_index]['Name'] if domain_index != -1 else ''
                sid_type = name['Use']
                type_desc = {
                    1: 'User',
                    2: 'Group',
                    3: 'Domain',
                    4: 'Alias',
                    5: 'WellKnownGroup',
                    6: 'DeletedAccount',
                    7: 'Invalid',
                    8: 'Unknown',
                    9: 'Computer',
                    10: 'Label'
                }.get(sid_type, 'Unknown')
                
                results.append({
                    'name': name['Name'],
                    'sid': sids[i],
                    'sid_type': sid_type,
                    'class': type_desc,
                    'domain': domain
                })
                
            return results
            
        except Exception as e:
            raise Exception(f"Failed to get group members: {str(e)}")
            
        finally:
            if 'policy_handle' in locals():
                lsad.hLsarClose(self._lsat_dce, policy_handle)          

    def get_local_groups(self):
        try:
            domain_handle = self._get_domain_handle(builtin=True)
            groups = []
            response = samr.hSamrEnumerateAliasesInDomain(self._samr_dce, domain_handle)
            for item in response['Buffer']['Buffer']:
                groups.append({
                    'name': item['Name'],
                    'comment': item['Description'] if hasattr(item, 'Description') else ''
                })
                
            return groups
            
        except samr.DCERPCSessionError as e:
            if str(e).find('STATUS_MORE_ENTRIES') < 0:
                raise
            raise Exception(f"Failed to enumerate local groups: {str(e)}")

    def get_local_users(self):
        try:
            domain_handle = self._get_domain_handle(builtin=False)
            
            users = []
            response = samr.hSamrEnumerateUsersInDomain(self._samr_dce, domain_handle, samr.USER_NORMAL_ACCOUNT)
            
            for user in response['Buffer']['Buffer']:
                user_rid = user['RelativeId']
                user_handle = samr.hSamrOpenUser(self._samr_dce, domain_handle, samr.MAXIMUM_ALLOWED, user_rid)['UserHandle']
                
                user_info = samr.hSamrQueryInformationUser2(self._samr_dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)['Buffer']['All']
                
                # Don't think there is a way to get user_type info unless using USER_INFO_3 struct
                #uac_obj = user_info['UserAccountControl']
                #uac_value = getattr(uac_obj, 'fields', {}).get('Data', uac_obj)
                
                # user_type_map = {
                #                 0: "Guest",
                #                 1: "User",
                #                 2: "Administrator"
                #             }
                            
                # user_type = user_type_map.get(priv_level, "Unknown")

                users.append({
                    'name': user['Name'],
                    'rid': user_rid,
                    'enabled': not bool(user_info['UserAccountControl'] & samr.USER_ACCOUNT_DISABLED),
                    'password_expired': bool(user_info['UserAccountControl'] & samr.USER_PASSWORD_EXPIRED),
                    'last_logon': self._filetime_to_datetime(user_info['LastLogon']),
                    'pwd_last_set': self._filetime_to_datetime(user_info['PasswordLastSet']),
                    'num_logins': user_info['LogonCount'],
                    'user_type': None,
                    'comment': user_info['AdminComment'] if hasattr(user_info, 'AdminComment') else ''
                })
                
                samr.hSamrCloseHandle(self._samr_dce, user_handle)
                
            return users
            
        except Exception as e:
            raise Exception(f"Failed to enumerate local users: {str(e)}")

    @staticmethod
    def _filetime_to_datetime(filetime: Dict[str, int]) -> Optional[datetime]:
        if filetime['LowPart'] == 0 and filetime['HighPart'] == 0:
            return None
            
        total = (filetime['HighPart'] << 32) + filetime['LowPart']
        total -= 116444736000000000
        total /= 10000000
        
        return datetime.fromtimestamp(total)