
import re
from enum import IntEnum
from lib import WMIHandler
from lib import PrintHandler
from impacket.examples.utils import parse_target

class SECURITY_LOGON_TYPE(IntEnum):
    Interactive = 2
    Network = 3
    Batch = 4
    Service = 5
    Unlock = 7
    NetworkCleartext = 8
    NewCredentials = 9
    RemoteInteractive = 10
    CachedInteractive = 11

class StateEnum(IntEnum):
    Unknown = 0
    Disabled = 1
    Queued = 2
    Ready = 3
    Running = 4

class RunlvelEnum(IntEnum):
    TASK_RUNLEVEL_LUA = 0
    TASK_RUNLEVEL_HIGHEST = 1

class ScheduledTaskPrincipal:
    def __init__(self):
        self.DisplayName = None
        self.GroupId = None
        self.Id = None
        self.LogonType = None
        self.RunLevel = None
        self.UserId = None

class ScheduledTaskTrigger:
    def __init__(self):
        self.Type = None
        self.Enabled = None
        self.EndBoundary = None
        self.ExecutionTimeLimit = None
        self.StartBoundary = None
        self.Duration = None
        self.Interval = None
        self.StopAtDurationEnd = None
        self.Properties = None

class ScheduledTaskAction:
    def __init__(self):
        self.Type = None
        self.Id = None
        self.Properties = None

class ScheduledTask:
    def __init__(self, name: str, principal: ScheduledTaskPrincipal, author: str, description: str, source: str, state: str, sddl: str, actions: ScheduledTaskAction, triggers: ScheduledTaskTrigger, enabled: str, taskpath: str, hidden: str, date: str, allowdemandstart: str, allowhardterminate: str, disallowstartifonbatteries: str, executiontimelimit: str, stopifgoingonbatteries: str):
        self.Name = name
        self.Principal = principal
        self.Author = author
        self.Description = description
        self.Source = source
        self.State = state
        self.SDDL = sddl
        self.Actions = actions
        self.Triggers = triggers
        self.Enabled = enabled
        self.TaskPath = taskpath
        self.Hidden = hidden
        self.Date = date
        self.AllowDemandStart = allowdemandstart
        self.AllowHardTerminate = allowhardterminate
        self.DisallowStartIfOnBatteries = disallowstartifonbatteries
        self.ExecutionTimeLimit = executiontimelimit
        self.StopIfGoingOnBatteries = stopifgoingonbatteries

def get_scheduled_tasks(wmi_conn, args):
    wmi_data = None
    try:
        # Impacket has a bug getting MSFT_ScheduledTask Settings property so we have to get everything except that
        # the Settings property has a property named MaintenanceSetting which sometimes does not exist and that throws an error in the WMI library
        # https://github.com/fortra/impacket/issues/1845
        wmi_data = wmi_conn.wmi_get('SELECT Actions, Author, Date, Description, Documentation, Principal, SecurityDescriptor, Source, State, TaskName, TaskPath, Triggers, URI, Version FROM MSFT_ScheduledTask')
        #wmi_data = wmi_conn.wmi_get('SELECT * FROM MSFT_ScheduledTask')
    except Exception as e:
        print("  [X] 'MSFT_ScheduledTask' WMI class unavailable (minimum supported versions of Windows: 8/2012)")
        print(e)

    if wmi_data is None:
        return

    for obj in wmi_data:
        data = wmi_conn.parse_wmi(obj)
        if 'filter' in args:
            if re.search("Microsoft", str(data["Author"])):
                continue
        
        state = StateEnum(int(data['State'])).name

        temp_principal = data['Principal']
        # Impacket bug needs to be fixed first
        #settings = data['Settings']
        actions = data['Actions']
        triggers = data['Triggers']

        principal = ScheduledTaskPrincipal()
        principal.DisplayName = temp_principal['DisplayName']
        principal.Id = temp_principal['Id']
        principal.GroupId = temp_principal['GroupId']
        temp_logon_type = temp_principal['LogonType']
        principal.LogonType = SECURITY_LOGON_TYPE(int(temp_logon_type)).name
        temp_run_level = temp_principal['RunLevel']
        principal.RunLevel = RunlvelEnum(int(temp_run_level)).name
        principal.UserId = temp_principal['UserId']

        actions_list = []
        for o in actions:
            action = ScheduledTaskAction()
            #This needs to be revisited - do obj.SystemProperties["__SUPERCLASS"].Value}
            # Currently not correct
            action.Type = obj['Actions']['qualifiers']['EmbeddedInstance']
            properties = {}
            for key, value in o.items():
                if key != "PSComputerName":
                    properties[key] = value
            action.Properties = properties
            actions_list.append(action)
        
        trigger_objects = []
        if triggers != None:
            for o in triggers:
                trigger = ScheduledTaskTrigger()
                #This needs to be revisited - do obj.SystemProperties["__CLASS"].Value}
                # Currently not correct
                trigger.Type = obj['Triggers']['qualifiers']['EmbeddedInstance']
                trigger.Enabled = o['Enabled']
                trigger.EndBoundary = o['EndBoundary']
                trigger.ExecutionTimeLimit = o['ExecutionTimeLimit']
                trigger.StartBoundary = o['StartBoundary']
                rep_obj = o['Repetition']
                trigger.Duration = rep_obj['Duration']
                trigger.Interval = rep_obj['Interval']
                trigger.StopAtDurationEnd = rep_obj['StopAtDurationEnd']

                properties = {}
                pattern = r"Id|Enabled|EndBoundary|ExecutionTimeLimit|StartBoundary|Repetition"
                for k, v in o.items():

                    if not re.match(pattern, k):
                        properties[k] = v

                trigger.Properties = properties
                trigger_objects.append(trigger)

        #Needs to be updated for the settings
        yield ScheduledTask(data['TaskName'], principal, data['Author'], data['Description'], data['Source'], state, data['SecurityDescriptor'], actions_list, trigger_objects, None, data['TaskPath'], None, data['Date'], None, None, None, None, None)

def format_results(schtask):
    
    print(f"  {'Name':<30}    :   {schtask.Name}")
    print(f"  {'Principal':<30}    :")
    print(f"      {'GroupId':<30}:   {schtask.Principal.GroupId}")
    print(f"      {'Id':<30}:   {schtask.Principal.Id}")
    print(f"      {'LogonType':<30}:   {schtask.Principal.LogonType}")
    print(f"      {'RunLevel':<30}:   {schtask.Principal.RunLevel}")
    print(f"      {'UserId':<30}:   {schtask.Principal.UserId}")

    print(f"  {'Author':<30}    :   {schtask.Author}")
    print(f"  {'Description':<30}    :   {schtask.Description}")
    print(f"  {'Source':<30}    :   {schtask.Source}")
    print(f"  {'State':<30}    :   {schtask.State}")
    print(f"  {'SDDL':<30}    :   {schtask.SDDL}")
    
    print(f"  {'Enabled':<30}    :   {schtask.Enabled}")
    print(f"  {'Date':<30}    :   {schtask.Date}")
    print(f"  {'AllowDemandStart':<30}    :   {schtask.AllowDemandStart}")
    print(f"  {'DisallowStartIfOnBatteries':<30}    :   {schtask.DisallowStartIfOnBatteries}")
    print(f"  {'ExecutionTimeLimit':<30}    :   {schtask.ExecutionTimeLimit}")
    print(f"  {'StopIfGoingOnBatteries':<30}    :   {schtask.StopIfGoingOnBatteries}")

    print(f"  {'Actions':<30}    :")
    print("      ------------------------------")
    for action in schtask.Actions:
        print(f"      {'Type':<30}:   {action.Type}")
        for key, val in action.Properties.items():
            if val is not None and val != '':
                print(f"      {key:<30}:   {val}")
        print("      ------------------------------")
    
    print(f"  {'Triggers':<30}    :")
    print("      ------------------------------")
    for trigger in schtask.Triggers:
        print(f"      {'Type':<30}:   {trigger.Type}")
        print(f"      {'Enabled':<30}:   {trigger.Enabled}")
        if trigger.StartBoundary is not None and trigger.StartBoundary != '':
            print(f"      {'StartBoundary':<30}:   {trigger.StartBoundary}")
        if trigger.EndBoundary is not None and trigger.EndBoundary != '':
            print(f"      {'EndBoundary':<30}:   {trigger.EndBoundary}")
        if trigger.ExecutionTimeLimit is not None and trigger.ExecutionTimeLimit != '':
            print(f"      {'ExecutionTimeLimit':<30}:   {trigger.ExecutionTimeLimit}")
        if trigger.Duration is not None and trigger.Duration != '':
            print(f"      {'Duration':<30}:   {trigger.Duration}")
        if trigger.Interval is not None and trigger.Interval != '':
            print(f"      {'Interval':<30}:   {trigger.Interval}")
        if trigger.StopAtDurationEnd is not None and trigger.StopAtDurationEnd != '':
            print(f"      {'StopAtDurationEnd':<30}:   {trigger.StopAtDurationEnd}")

        if trigger.Properties is not None:
            for key, val in trigger.Properties.items():
                if val is not None and val != '':
                    print(f"      {key:<30}:   {val}")
        print("      ------------------------------")
    print()

def command_base(options):
    command = 'ScheduledTasks'
    description = 'Scheduled tasks (via WMI) that aren\'t authored by \'Microsoft\', "-full" dumps all Scheduled tasks'
    command_group = ['misc', 'remote']
    wmi_namespace = "//./Root/Microsoft/Windows/TaskScheduler"
    
    args = ''
    if options.command_args:
        module_args = options.command_args[command.lower()]
        if module_args:
            args = module_args.split()
    domain, username, password, address = parse_target(options.target)

    PrintHandler.show_banner(command)
    try:
        wmi_conn = WMIHandler(address, wmi_namespace, username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
        wmi_conn.connect()
        for sch_task in get_scheduled_tasks(wmi_conn ,args):
            if sch_task is not None:
                format_results(sch_task)
    except KeyboardInterrupt:
        wmi_conn.close()
    except Exception as e:
        print(e)

    wmi_conn.close()