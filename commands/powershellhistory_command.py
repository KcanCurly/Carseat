
import re
from lib import MiscUtil
from lib import SMBHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class PowerShellHistory:
    def __init__(self, username: str, consolehistorypath: str, match: str, contextjoined: str):
        self.UserName = username
        self.ConsoleHistoryPath = consolehistorypath
        self.Match = match
        self.ContextJoined = contextjoined

def get_powershell_history(smb_conn, args):
    share = "C$"
    user_path = '\\Users'
    ps_regex = MiscUtil.get_process_cmdline_regex()
    context = 3
    if len(args) >= 1:
        all_args = " ".join(args)
        ps_regex = [re.compile(all_args, re.IGNORECASE | re.MULTILINE)]

    directory_listing = smb_conn.list_directory(share, user_path)
    for f in directory_listing:
        if f.is_directory():
            if f.get_longname() == '.' or f.get_longname() == '..' or f.get_longname() == 'Public' or f.get_longname() == 'Default' or f.get_longname() == 'Default User' or f.get_longname() == 'All Users':
                continue
            
            user_name = f.get_longname()
            partial_path = f'{user_path}\\{user_name}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline'
            ps_con_hist_path = f'{user_path}\\{user_name}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt'
            fixed_path = f'C:{ps_con_hist_path}'
            if not smb_conn.file_exists(share, ps_con_hist_path):
                continue
            
            content = smb_conn.show_file_content(share, partial_path, 'ConsoleHost_history.txt')
            for reg in ps_regex:
                m = reg.search(content)
                if not m:
                    continue
                context_lines = []
                script_block_parts = content.splitlines()
                for i in script_block_parts:
                    print(i)
                    if m.group() not in script_block_parts[i]:
                        continue

                    printed = 0
                    for j in range(1, i + 1):
                        if i - j <= 0 or printed >= context:
                            break
                        
                        if script_block_parts[i - j].strip() == "":
                            continue
                            
                        context_lines.append(script_block_parts[i - j].strip())
                        printed += 1

                    printed = 0
                    context_lines.append(m.group().strip())
                    for j in range(1, len(script_block_parts)):
                        if printed >= context or i + j >= len(script_block_parts):
                            break
                            
                        if script_block_parts[i + j].strip() == "":
                            continue
                            
                        context_lines.append(script_block_parts[i + j].strip())
                        printed += 1

                    break

                context_joined = "\n".join(context_lines)
                yield PowerShellHistory(user_name, fixed_path, m.group(), context_joined)

def command_base(options):
    command = 'PowerShellHistory'
    description = 'Searches PowerShell console history files for sensitive regex matches.'
    command_group = ['user', 'remote']

    args = ''
    if options.command_args:
        module_args = options.command_args[command.lower()]
        if module_args:
            args = module_args.split()

    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        smb_conn = SMBHandler(address, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        for ps_hist in get_powershell_history(smb_conn, args):
            if ps_hist is not None:
                PrintHandler.print_props(ps_hist)
    except KeyboardInterrupt:
        smb_conn.close()
    except Exception as e:
        print(e)

    smb_conn.close()
