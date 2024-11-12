
from lib import PrintHandler
from impacket.examples.utils import parse_target


def command_base(options):
    command = 'RDPSessions'
    description = 'Current incoming RDP sessions (argument == computername to enumerate)'
    command_group = ['system', 'remote']

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    #WTSOpenServerA (wtsapi32.h)
    print('Command not implemented')
    print()