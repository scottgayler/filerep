## Edited VMware provided python script to remove userconfirmation
##              Commenting out the user verification prompt lines 344-348

import sys
import os
import subprocess
from datetime import datetime
import shutil
import json
import re
import traceback

sys.path.append(os.environ['VMWARE_PYTHON_PATH'])
isLinux = os.name == 'posix'
if not isLinux:
    SERVICE_CTL = '"' + os.getenv('VMWARE_CIS_HOME') + '\\bin\\service-control.bat' + '"'
    if sys.version_info[0] >= 3:
        from six.moves import winreg
    else:
        import _winreg as winreg
    WReg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
    key = winreg.OpenKey(WReg, r"SOFTWARE\VMware, Inc.\vCenter Server")
    vcbuild = winreg.QueryValueEx(key, 'BuildNumber')[0]
    vcversion = winreg.QueryValueEx(key, 'ProductVersion')[0]
    """
    Windows file paths needs to be updated
    vmon_config_file = "/usr/lib/vmware-vmon/java-wrapper-vmon"
    vum_config_file = "/usr/lib/vmware-updatemgr/bin/jetty/start.ini"
    analytics_jar_file = "/usr/lib/vmware/common-jars/log4j-core-2.8.2.jar"
    dbcc_jar_file = "/usr/lib/vmware-dbcc/lib/log4j-core-2.8.2.jar"
    """
    now = datetime.now()
    date_time = now.strftime("%d-%b-%y-%H-%M-%S")
    print("This Script is not configured to run on Windows vCenter Server, please follow the KB https://kb.vmware.com/s/article/87081 to apply the workaround steps")
    from cis.tools import get_install_parameter
    exit(0)
else:
    SERVICE_CTL = 'service-control'
    now = datetime.now()
    date_time = now.strftime("%d-%b-%y-%H-%M-%S")
    from cis.tools import get_install_parameter
    vmon_config_file = "/usr/lib/vmware-vmon/java-wrapper-vmon"
    vum_config_file = "/usr/lib/vmware-updatemgr/bin/jetty/start.ini"
    analytics_jar_file = "/usr/lib/vmware/common-jars/log4j-core-2.8.2.jar"
    dbcc_jar_file = "/usr/lib/vmware-dbcc/lib/log4j-core-2.8.2.jar"
    cm_jar_file = "/usr/lib/vmware-cm/lib/log4j-core.jar"
    stsd_config_file = "/etc/rc.d/init.d/vmware-stsd"
    idmd_config_file = "/etc/rc.d/init.d/vmware-sts-idmd"
    pscclient_config_file = "/etc/rc.d/init.d/vmware-psc-client"
    with open("/etc/applmgmt/appliance/update.conf") as f:
        data = json.load(f)
        vcbuild = data['build']
    f = open("/etc/issue")
    for line in f:
        if not line.strip():
            continue
        else:
            vcversion = line
            break
    vcversion = vcversion.rsplit(' ', 1)[1]
    vcversion = vcversion.strip()

deployment_type = get_install_parameter('deployment.node.type')

if sys.version_info[0] < 3:
    inputfunction = raw_input
else:
    inputfunction = input

def execute_cmd(cmd, shellvalue=True, stdin=None, quiet=False):
    p = None
    p = subprocess.Popen(cmd, shell=shellvalue, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdout, stderr) = p.communicate()
    return p.returncode, stdout, stderr

def color_green(input_string):
    OKGREEN = '\033[92m'
    ENDC = '\033[0m'
    new_string = OKGREEN + input_string + ENDC
    return new_string

def color_red(input_string):
    OKRED = '\033[91m'
    ENDC = '\033[0m'
    new_string = OKRED + input_string + ENDC
    return new_string

def backup_config_file(filename,dest_path=None):
    print("...Taking Backup of file %s" % filename)
    try:
        if dest_path:
            parent_path, base_filename = os.path.split(filename)
            backupfilename = dest_path + base_filename + "_backup_" + date_time
        else:
            backupfilename = filename + "_backup_" + date_time
        shutil.copyfile(filename, backupfilename)
        print("...Successfully completed the backup - %s" % backupfilename)
    except Exception as e:
        print(color_red("Script terminated - Failed taking backup of Config file " + filename + "Operation failed "
                                                                                                 "with error" + str(e)))
        exit(1)

def check_if_string_in_file(file_name, string_to_search):
    with open(file_name, 'r') as file_contents:
        for line in file_contents:
            if string_to_search in line:
                return True
    return False

def add_string_to_file(filename, old_string, new_string):
    file_handle = open(filename, 'r')
    file_contents = file_handle.read()
    file_handle.close()
    file_contents = (re.sub(old_string, new_string, file_contents))
    file_handle = open(filename, 'w')
    file_handle.write(file_contents)
    file_handle.close()

def add_string_to_end_of_file(filename, new_string):
    with open(filename, "a") as file_object:
        file_object.write(new_string)
    return True

def vmon_remediation(config_filename):
    print("\nRemediating vMon Config files")
    if not check_if_string_in_file(config_filename, "-Dlog4j2.formatMsgNoLookups=true"):
        backup_config_file(config_filename)
        print("...Updating Config file")
        if check_if_string_in_file(config_filename,'exec $java_start_bin $jvm_dynargs "$@"'):
            new_config_entries='log4j_arg="-Dlog4j2.formatMsgNoLookups=true"' + "\n" + 'exec $java_start_bin $jvm_dynargs $log4j_arg "$@"'
            add_string_to_file(config_filename, 'exec \$java_start_bin \$jvm_dynargs "\$@"', new_config_entries)
        elif check_if_string_in_file(config_filename,'exec $java_start_bin $jvm_dynargs $security_dynargs $original_args'):
            new_config_entries='log4j_arg="-Dlog4j2.formatMsgNoLookups=true"' + "\n" + 'exec $java_start_bin $jvm_dynargs $log4j_arg  $security_dynargs $original_args'
            add_string_to_file(config_filename, 'exec \$java_start_bin \$jvm_dynargs \$security_dynargs \$original_args', new_config_entries)
        print("...Completed Config file update")
    else:
        print("...Config files already have the entries to workaround the VMSA")
        print("...Proceeding further to check other services")
    print("...Stopping all Services")
    restart_all_services("stop")
    print("...Starting all Services")
    restart_all_services("start")
    print("...Successfully Started All Services")
    print(color_green("...Completed remediating vMon services"))
   
def vum_remediation(config_filename):
    print("\nRemediating VMware Update Manager Config files")
    if check_if_string_in_file(config_filename, "-Dlog4j2.formatMsgNoLookups=true"):
        print("...Config files already have the entries to workaround the VMSA")
    else:
        backup_config_file(config_filename)
        print("...Updating Config file")
        add_string_to_end_of_file(config_filename,'-Dlog4j2.formatMsgNoLookups=true')
        print("...Completed Config file update")
    print("...Restarting Update Manager Service")
    restart_service("vmware-updatemgr")
    print("...Successfully restarted Update Manager Service")
    print(color_green("...Completed remediating Update Manager service"))

def analytics_remediation(config_filename):
    print("\nRemediating Analytics Service Config files")
    backup_config_file(config_filename)
    cmd = 'zip -q -d ' + config_filename + ' org/apache/logging/log4j/core/lookup/JndiLookup.class'
    print("...Updating Config file")
    (code, result, err) = execute_cmd(cmd, True, None)
    if code == 0:
        print("...Successfully updated the Jar file")
    elif("Nothing to do" in result.decode('utf-8').strip()):
        print("...Required Changes Already exists in the Jar file")
    print("...Restarting Analytics Service")
    restart_service("vmware-analytics")
    print("...Successfully restarted Analytics Service")
    print(color_green("...Completed remediating Analytics service"))

def dbcc_remediation(config_filename):
    global skip_dbcc
    skip_dbcc = False
    print("\nRemediating DBCC Utility Config files")
    if os.path.isfile(config_filename):
        backup_config_file(config_filename)
        cmd = 'zip -q -d ' + config_filename + ' org/apache/logging/log4j/core/lookup/JndiLookup.class'
        print("...Updating Config file")
        (code, result, err) = execute_cmd(cmd, True, None)
        if code == 0:
            print("...Successfully updated the Jar file")
        elif("Nothing to do" in result.decode('utf-8').strip()):
            print("...Required Changes Already exists in the Jar file")
            print(color_green("...Completed remediating DBCC configuration"))
    else:
        skip_dbcc = True
        print(color_green("Skipping DBCC Remediation as Log4j Jar file %s does not exist on this VC build") % config_filename)

def cm_remediation(config_filename):
    print("\nRemediating CM Service Config files")
    backup_config_file(config_filename)
    cmd = 'zip -q -d ' + config_filename + ' org/apache/logging/log4j/core/lookup/JndiLookup.class'
    print("...Updating Config file")
    (code, result, err) = execute_cmd(cmd, True, None)
    if code == 0:
        print("...Successfully updated the Jar file")
    elif("Nothing to do" in result.decode('utf-8').strip()):
        print("...Required Changes Already exists in the Jar file")
    print("...Restarting CM Service")
    restart_service("vmware-cm")
    print("...Successfully restarted CM Service")
    print(color_green("...Completed remediating CM service"))

def stsd_remediation(config_filename):
    print("\nRemediating STSD Config files")
    if not check_if_string_in_file(config_filename, "-Dlog4j2.formatMsgNoLookups=true"):
        backup_config_file(config_filename,"/root/")
        print("...Updating Config file")
        new_config_entries='           -Dlog4j2.formatMsgNoLookups=true \\' + "\n" + '            $DAEMON_CLASS start'
        add_string_to_file(config_filename, '           \$DAEMON_CLASS start', new_config_entries)
        print("...Completed Config file update")
    else:
        print("...Config files already have the entries to workaround the VMSA")
        print("...Proceeding further to check other services")
    print("...Restarting vmware-stsd Service")
    restart_service("vmware-stsd")
    print("...Successfully restarted vmware-stsd Service")
    print(color_green("...Completed remediating vmware-stsd service"))

def idmd_remediation(config_filename):
    print("\nRemediating IDMD Config files")
    if not check_if_string_in_file(config_filename, "-Dlog4j2.formatMsgNoLookups=true"):
        backup_config_file(config_filename,"/root/")
        print("...Updating Config file")
        new_config_entries='                  -Dlog4j2.formatMsgNoLookups=true \\' + "\n" + '                  $DEBUG_OPTS'
        add_string_to_file(config_filename, "                  \$DEBUG_OPTS", new_config_entries)
        print("...Completed Config file update")
    else:
        print("...Config files already have the entries to workaround the VMSA")
        print("...Proceeding further to check other services")
    print("...Restarting vmware-stsd-idmd Service")
    restart_service("vmware-sts-idmd")
    print("...Successfully restarted vmware-sts-idmd Service")
    print(color_green("...Completed remediating vmware-sts-idmd service"))

def pscclient_remediation(config_filename):
    print("\nRemediating PSC Client Config files")
    if not check_if_string_in_file(config_filename, "-Dlog4j2.formatMsgNoLookups=true"):
        backup_config_file(config_filename,"/root/")
        print("...Updating Config file")
        new_config_entries='           -Dlog4j2.formatMsgNoLookups=true \\' + "\n" + '             $DAEMON_CLASS start'
        add_string_to_file(config_filename, '           \$DAEMON_CLASS start', new_config_entries)
        print("...Completed Config file update")
    else:
        print("...Config files already have the entries to workaround the VMSA")
        print("...Proceeding further to check other services")
    print("...Restarting vmware-psc-client Service")
    restart_service("vmware-psc-client")
    print("...Successfully restarted vmware-psc-client Service")
    print(color_green("...Completed remediating vmware-psc-client service"))

def verify_vmon_mitigation():
    status = False
    cmd = ' ps auxww | grep formatMsgNoLookups'
    (code, result, err) = execute_cmd(cmd)
    ps_result = result.decode('utf-8').split('\n')
    for line in ps_result:
        if '.launcher' in line:
            if '-Dlog4j2.formatMsgNoLookups=true' in line:
                status = True
            else:
                status = False
    return status

def verify_MsgNoLookups_with_ps_command(process_string):
    status = False
    cmd = ' ps auxww | grep formatMsgNoLookups'
    (code, result, err) = execute_cmd(cmd)
    ps_result = result.decode('utf-8').split('\n')
    for line in ps_result:
        if process_string in line:
            if '-Dlog4j2.formatMsgNoLookups=true' in line:
                status = True
            else:
                status = False
    return status

def verify_vum_mitigation():
    log4j2_string = "log4j2.formatMsgNoLookups = true (/usr/lib/vmware-updatemgr/bin/jetty/start.ini)"
    cmd = ' cd /usr/lib/vmware-updatemgr/bin/jetty/ && java -jar start.jar --list-config'
    (code, result, err) = execute_cmd(cmd)
    if log4j2_string in result.decode('utf-8').replace('\n','\n'):
        return True
    else:
        return False

def verify_jndilookup(jar_path):
    cmd = ' grep -i jndilookup ' +jar_path + ' | wc -l'
    (code, result, err) = execute_cmd(cmd)
    a = result.decode('utf-8').strip()
    if a == '0':
        return True
    else:
        return False

"""
This function helps to restart all services
"""
def restart_all_services(action):
    if action in ['stop','Stop','STOP']:
        service_action = " --stop"
    elif action in ['start','Start','START']:
        service_action = " --start"
    cmd = SERVICE_CTL + service_action + ' --all '
    try:
        (code, result, err) = execute_cmd(cmd, True, None)
        if code != 0:
            return (False,result,err)
        else:
            return (True,result,err)
    except Exception as e:
        msg = 'Error while performing all services stop/start operation : {0}'.format(e)
        print(msg)
        return (False,result,err)

"""
This function helps to restart an individual service
It accepts service name as argument
"""
def restart_service(service_name):
    try:
        cmd = SERVICE_CTL + ' --stop ' + service_name
        (code, result, err) = execute_cmd(cmd, True, None)
        cmd = SERVICE_CTL + ' --start ' + service_name
        (code, result, err) = execute_cmd(cmd, True, None)
        if code != 0:
            return False
        else:
            return True
    except Exception as e:
        msg = 'Error while restarting service : {0}'.format(e)
        print(msg)
        return False

def main():
    vmonstatus = vumstatus = analyticsstatus = dbccstatus = cmstatus = stsdstatus = stsidmdstatus = pscclientstatus = True
    verifystsd = verifyidmd = verifypscclient = False
    do_analytics = False
    print("This script will help to automate the steps described in VMware KB https://kb.vmware.com/s/article/87081\n")
    #userconfirmation = inputfunction("All Services will be restarted by the script to mitigate the VMSA, Please enter YES to proceed further or NO to Exit [[Yes/No/Y/N]] ? ")
    #if userconfirmation.lower() not in ['y','Y','Yes','YES','yes','yES','yeS']:
    #    print(color_green("Terminating the script based on user input, you may follow the steps described in https://kb.vmware.com/s/article/87081 "))
    #    traceback.print_exc()
    #    exit(1)
    try:
        if vcversion.startswith("7.0") or vcversion.startswith("6.7") or vcversion.startswith("6.5"):
            vmon_remediation(vmon_config_file)
        if vcversion.startswith("6.5") or vcversion.startswith("6.7"):
            if deployment_type in ["embedded","infrastructure"]:
                verifystsd = True
                verifyidmd = True
                stsd_remediation(stsd_config_file)
                idmd_remediation(idmd_config_file)
            else:
                print(color_green("\nSkipping STSD & IDMD checks as this is a Management Node pointing to External PSC"))
        if vcversion.startswith("6.5"):
            if deployment_type in ["embedded","infrastructure"]:
                verifypscclient = True
                pscclient_remediation(pscclient_config_file)
            else:
                print(color_green("\nSkipping psc-client check as this is a Management Node pointing to External PSC"))
        if vcversion.startswith("7.0"):
            vum_remediation(vum_config_file)
        if vcversion.startswith("7.0") or (vcversion.startswith("6.7") and int(vcversion.split('.')[3]) <= 50000):
            do_analytics = True
            analytics_remediation(analytics_jar_file)
        if vcversion.startswith("7.0"):
            dbcc_remediation(dbcc_jar_file)
        if vcversion.startswith("6.7") or vcversion.startswith("6.5"):
            cm_remediation(cm_jar_file)
    except Exception as e:
        traceback.print_exc()
        print(color_red("Script failed with error - Please follow the KB https://kb.vmware.com/s/article/87081 manually" + str(e)))
        exit()
    
    print("\nVerifying the vulnerability status after applying the workaround :\n")
    print("..Verifying the status of vMon Services")
    if verify_vmon_mitigation():
        print(color_green("....SUCCESS"))
    else:
        print(color_red("....FAILED"))
        vmonstatus = False
    
    if verifystsd:
        print("..Verifying the status of vmware-stsd Service")
        if verify_MsgNoLookups_with_ps_command("procname vmware-stsd"):
            print(color_green("....SUCCESS"))
        else:
            print(color_red("....FAILED"))
            stsdstatus = False

    if verifyidmd:
        print("..Verifying the status of vmware-sts-idmd Service")
        if verify_MsgNoLookups_with_ps_command("procname vmware-sts-idmd"):
            print(color_green("....SUCCESS"))
        else:
            print(color_red("....FAILED"))
            stsidmdstatus = False

    if verifypscclient:
        print("..Verifying the status of vmware-psc-client Service")
        if verify_MsgNoLookups_with_ps_command("procname vmware-psc-client"):
            print(color_green("....SUCCESS"))
        else:
            print(color_red("....FAILED"))
            pscclientstatus = False

    if vcversion.startswith("7.0"):
        print("..Verifying the status of VMware Update Manager")
        if verify_vum_mitigation():
            print(color_green("....SUCCESS"))
        else:
            print(color_red("....FAILED"))
            vumstatus = False

    if (do_analytics):
        print("..Verifying the status of VMware Analytics Service")
        if verify_jndilookup("/usr/lib/vmware/common-jars/log4j-core-2.8.2.jar"):
            print(color_green("....SUCCESS"))
        else:
            print(color_red("....FAILED"))
            analyticsstatus = False
    
    if vcversion.startswith("7.0"):
        print("..Verifying the status of DBCC Utility")
        if skip_dbcc:
            print(color_green("....SKIPPED (Not Applicable)"))
        elif verify_jndilookup("/usr/lib/vmware-dbcc/lib/log4j-core-2.8.2.jar"):
            print(color_green("....SUCCESS"))
        else:
            print(color_red("....FAILED"))
            dbccstatus = False
    
    if vcversion.startswith("6.7") or vcversion.startswith("6.5"):
        print("..Verifying the status of CM Service")
        if verify_jndilookup("/usr/lib/vmware-cm/lib/log4j-core.jar"):
            print(color_green("....SUCCESS"))
        else:
            print(color_red("....FAILED"))
            cmstatus = False

    if vmonstatus and vumstatus and analyticsstatus and dbccstatus and cmstatus:
        print(color_green("Successfuly applied the workaround steps in KB 87081 to mitigate the VMSA-2021-0028"))
    else:
        print(color_red("Script failed to mitigate some services, please follow the manual steps in KB 87081 to mitigate the VMSA-2021-0028"))
    

if __name__ == "__main__":
    main()
