
from datetime import datetime
from lib import SAMRHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class LocalUser:
    def __init__(self, computername: str, username: str, enabled: bool, rid: int, usertype: str, comment: str, pwdlastset: datetime, lastlogon: str, numlogins: str):
        self.ComputerName = computername
        self.UserName = username
        self.Enabled = enabled
        self.Rid = rid
        self.UserType = usertype
        self.Comment = comment
        self.PwdLastSet = pwdlastset
        self.LastLogon = lastlogon
        self.NumLogins = numlogins

def get_local_users(samr_conn, computer):
    computername = computer

    local_users = samr_conn.get_local_users()
    for user in local_users:
        yield LocalUser(computername, user['name'], user['enabled'], user['rid'], user['user_type'], user['comment'], user['pwd_last_set'], user['last_logon'], user['num_logins'])

def command_base(options):
    command = 'LocalUsers'
    description = 'Local users, whether they\'re active/disabled, and pwd last set (argument == computername to enumerate)'
    command_group = ['system', 'remote']

    #args = ''
    domain, username, password, address = parse_target(options.target)

    #TODO: Fix getting some extra info
    #need USER_INFO_3 structure
    #don't know if i can get this with samr

    PrintHandler.show_banner(command)
    try:
        samr_conn = SAMRHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        samr_conn.connect()
        for users in get_local_users(samr_conn, address):
            if users is not None:
                PrintHandler.print_props(users)
                print()
    except KeyboardInterrupt:
        samr_conn.disconnect()
    except Exception as e:
        print(e)

    samr_conn.disconnect()