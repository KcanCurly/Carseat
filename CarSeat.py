
import os
import sys
import importlib
import argparse
import time
from impacket.examples import logger
#from impacket.examples.utils import parse_target

def print_banner():
    version = "1.0"
    print(f"""
 CarSeat: A junior Seatbelt\n
    ||   L   ||
    ||   ^   ||
    |/-->&<--\\|
    | /     \\ |
    | | v{version}| |
    | |     | |
   //(_\\___/_)\\\\
   \\\\_()___()_//
    `+---I---+'
    """)

def parse_module_commands(commands):
    command_args = {}
    if isinstance(commands, str):
        commands = [commands]
    command_string = " ".join(commands)
    module_splits = [cmd.strip() for cmd in command_string.split(',')]
    
    for module_str in module_splits:
        parts = module_str.split()
        if parts:
            module_name = parts[0].lower().strip()
            module_args = " ".join(parts[1:]) if len(parts) > 1 else ""
            command_args[module_name] = module_args
            
    return command_args

def process_commands(options):
    if hasattr(options, 'group') and options.group:
        options.command_args = {}
        commands_dir = "commands"
        group_commands = []        
        for file in os.listdir(commands_dir):
            if file.endswith('_command.py'):
                try:
                    module_name = file[:-3]
                    module = importlib.import_module(f"commands.{module_name}")
                    
                    if hasattr(module, "command_base"):
                        import inspect
                        source = inspect.getsource(module.command_base)
                        if "command_group" in source:
                            if f"'{options.group}'" in source or f'"{options.group}"' in source:
                                group_commands.append(module)
                except ImportError:
                    print(f"Warning: Could not import {module_name}")
                except Exception as e:
                    print(f"Warning: Error processing {module_name}: {e}")
        
        if group_commands:
            for module in group_commands:
                try:
                    module.command_base(options)
                except Exception as e:
                    print(f"Error executing {module.__name__}: {e}")
        else:
            print(f"Error: No commands found for group '{options.group}'")
            
    else:
        command_args = parse_module_commands(options.command)
        options.command_args = command_args
        for module_name, args in command_args.items():
            target_command = f'{module_name}_command'
            try:
                module = importlib.import_module(f"commands.{target_command}")
                
                if hasattr(module, "command_base"):
                    module.command_base(options)
                else:
                    print(f"Error: {target_command} does not have a command_base function")
            except ImportError:
                print(f"Error: Command '{module_name}' not found")
            except TypeError as e:
                print(f"Error: {e}")

def main():
    parser = argparse.ArgumentParser(add_help=True, description="Carseat: A junior Seatbelt")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('command', nargs='*', default=' ', help='carseat command/module to run')
    parser.add_argument('-group', action='store', help='group commands together')
    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                            'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If '
                                                                            'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    
    if len(sys.argv) == 1:
       parser.print_help()
       sys.exit(1)
    options = parser.parse_args()

    print_banner()

    start_time = time.time()
    logger.init()

    process_commands(options)

    end_time = time.time()
    elapsed_time = end_time - start_time

    print(f"\n\n[*] Completed collection in {elapsed_time:.2f} seconds\n")

if __name__ == "__main__":
    main()
