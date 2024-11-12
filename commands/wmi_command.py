
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class WMI_Data:
    def __init__(self, queryresults: dict):
        self.QueryResults = queryresults

def get_wmi(wmi_conn, query):
    searcher = wmi_conn.wmi_get(query)
    
    yield WMI_Data(searcher)

def format_results(wmi):
    for query_result in wmi.QueryResults:
        for key, value in sorted(query_result.items()):
            if value['value'] is None:
                continue
                
            value_type = type(value)
            value_name = str(key) if key is not None else ""
            if isinstance(value, (list, tuple)):
                print_array_value(value_type, value_name, value)
            else:
                print(f"  {value_name:<30}: {value['value']}")        
        print()

def print_array_value(value_type, value_name, value):
    elem_type = type(value[0]) if value else str
    name = f"{value_name}({value_type.__name__})"
    if elem_type == str:
        print(f"  {name:<30}:")
        for s in value:
            print(f"      {s}")
    else:
        str_values = [str(x) for x in value]
        v = ",".join(str_values)
        print(f"  {name:<30}: {v}")

def command_base(options):
    command = 'WMI'
    description = 'Runs a specified WMI query'
    command_group = ['system', 'remote']
    wmi_namespace = "//./root/CIMv2"

    # This may be problematic
    args = []
    wmi_query = 'Select * from Win32_ComputerSystem'
    if options.command_args:
        module_args = options.command_args[command.lower()]
        if module_args:
            args = module_args.split()

    print(args)
    if len(args) == 1:
        wmi_query = args[0]
    elif len(args) == 2:
        wmi_namespace == args[0]
        wmi_query = args[1]
    
    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for wmi in get_wmi(wmi_conn, wmi_query):
            if wmi is not None:
                format_results(wmi)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()
