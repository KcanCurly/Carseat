
from lib import PrintHandler
from lib import SAMRHandler
from impacket.examples.utils import parse_target

class LocalGroupMembership:
    def __init__(self, computername: str, groupname: str, groupcomment: str, members: list):
        self.ComputerName = computername
        self.GroupName = groupname
        self.GroupComment = groupcomment
        self.Members = members

def get_local_groups(samr_conn, args, computer):
    computer_name = computer
    if len(args) >= 1:
        print('All Local Groups (and memberships)\n\n')
    else:
        print('Non-empty Local Groups (and memberships)\n\n')

    groups = samr_conn.get_local_groups()
    for group in groups:
        members = samr_conn.get_local_group_members(group['name'])
        if members:
            yield LocalGroupMembership(computer_name, group['name'], group['comment'], members)

def format_results(group):
    if group == None:
        return

    print(f"  ** {group.ComputerName}\\{group.GroupName} ** ({group.GroupComment})\n")
    if group.Members is not None:
        for member in group.Members:
            print(f'  {member['class']:<15} {member['domain']}\\{member['name']:<40} {member['sid']}')
    print()

def command_base(options):
    command = 'LocalGroups'
    description = 'Non-empty local groups, "-full" displays all groups (argument == computername to enumerate)'
    command_group = ['system', 'remote']

    args = ''
    domain, username, password, address = parse_target(options.target)

    #TODO: Fix getting comments
    #need LOCALGROUP_INFO_1 structure
    #don't know if i can get this with samr
    
    PrintHandler.show_banner(command)
    try:
        samr_conn = SAMRHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        samr_conn.connect()
        for groups in get_local_groups(samr_conn, args, address):
            if groups is not None:
                format_results(groups)
    except KeyboardInterrupt:
        samr_conn.disconnect()
    except Exception as e:
        print(e)

    samr_conn.disconnect()
