import lxml.etree as le
import re
import os
import datetime
import shutil

CURL_PUSH_TELEMETRY = \
    "curl -X POST 'http://localhost:15080/analytics/telemetry/ph/api/hyper/send?_c&_i=test' " \
    "-d 'lorem ipsum' " \
    "-H 'Content-Type: application/json'  " \
    "-v  " \
    "2>&1  " \
    "| grep -e 'HTTP/1.1 '"

CURL_DATA_APP_AGENTS_CREATE = \
    "curl -X POST   'http://localhost:15080/analytics/ph/api/dataapp/agent?_c=test&_i=1' \
    -H 'Accept-Encoding: gzip, deflate' \
    -H 'X-Deployment-Secret: abc' \
    -H 'accept: application/vapi' \
    -H 'Connection: keep-alive' \
    -H 'Content-Type: application/json' \
    -H 'Content-Length: 2' \
    -H 'Host: localhost:15080' \
    -H 'User-Agent: vAPI/2.100.0 Java/1.8.0_261 (Linux; 4.19.160-6.ph3; amd64)' -v 2>&1 -d '{}' " \
    "| grep -e 'HTTP/1.1 '"

CURL_DATA_APP_COLLECT = \
    "curl -X POST   'http://localhost:15080/analytics/ph/api/dataapp/agent?action=collect&_c=test&_i=1' \
    -H 'Accept-Encoding: gzip, deflate' \
    -H 'X-Deployment-Secret: abc' \
    -H 'accept: application/vapi' \
    -H 'Connection: keep-alive' \
    -H 'Content-Type: application/json' \
    -H 'Content-Length: 2' \
    -H 'Host: localhost:15080' \
    -H 'User-Agent: vAPI/2.100.0 Java/1.8.0_261 (Linux; 4.19.160-6.ph3; amd64)' -v 2>&1 -d '{}' " \
    "| grep -e 'HTTP/1.1 '"

BEAN_HEADER_CLASS = 'com.vmware.vim.vmomi.server.http.impl.ServiceImpl'

RESTART_CMD = 'service-control --stop analytics && service-control --start analytics'

FILTERED_SERVICE_PATHS = ["${ph.telemetry.root.path}", "${ph.phapi.path}", "${ph.phstgapi.path}"]

REVERT_CHECK_KB_MANUAL = "Reverting the patching. " \
                         "Read the KB for the manual patching process and " \
                         "report the reason of the failure."

RPM_VERSION_CMD = 'rpm -qa | grep analytics'
RPM_VERSION = ""

CONFIG_FILE = 'ph-web.xml'
CONFIG_FILE_PATH = '/etc/vmware-analytics/'
BACKUP_FILE_PATH = '/var/log/vmware/analytics/'
FULL_CONFIG_URI = CONFIG_FILE_PATH + CONFIG_FILE
FULL_CONFIG_URI_BACKUP = ""
RUN_TIME_STAMP = ""


def backup_configs():
    print("\nBacking up the config file : " + FULL_CONFIG_URI)
    global FULL_CONFIG_URI_BACKUP

    FULL_CONFIG_URI_BACKUP = BACKUP_FILE_PATH + CONFIG_FILE + \
                             '---BEFORE_PATCH---' + RPM_VERSION + '-' + RUN_TIME_STAMP + '.backup'

    shutil.copyfile(FULL_CONFIG_URI, FULL_CONFIG_URI_BACKUP)
    print("OK : Config file backed up as : " + FULL_CONFIG_URI_BACKUP + "\n")


def check_for_open_vulnerabilities():
    print("\nChecking for open vulnerabilities : ")

    # will return "HTTP/1.1 201" if the endpoint is available or 404 if disabled
    curl_push_stream = os.popen(CURL_PUSH_TELEMETRY)
    output = curl_push_stream.read()
    print("TEST : Push telemetry : " + str(output).rstrip())
    if "HTTP/1.1 404" not in output:
        print("WARNING : Vulnerability found.")
        return True

    # will return "HTTP/1.1 201" if the endpoint is available or 404 if disabled
    curl_data_app_agent_create = os.popen(CURL_DATA_APP_AGENTS_CREATE)
    output = curl_data_app_agent_create.read()
    print("TEST : Create data app agent : " + str(output).rstrip())
    if "HTTP/1.1 404" not in output:
        print("WARNING : Vulnerability found.")
        return True

    # will return "HTTP/1.1 200" if the endpoint is available or 404 if disabled
    curl_data_app_collect = os.popen(CURL_DATA_APP_COLLECT)
    output = curl_data_app_collect.read()
    print("TEST Data app collect : " + str(output).rstrip())
    if "HTTP/1.1 404" not in output:
        print("WARNING : Vulnerability found.")
        return True

    print("OK : Vulnerabilities were NOT found!")
    return False


def patch_configs():
    print("\nPatching the config file: " + FULL_CONFIG_URI)
    with open(FULL_CONFIG_URI, 'r') as f:
        doc = le.parse(f)

        service_lst = []
        for elem in doc.xpath('//*[attribute::name]'):
            service = elem.getparent()
            if service.attrib['class'] == BEAN_HEADER_CLASS \
                and elem.attrib['name'] == 'path' \
                and elem.attrib['value'] in FILTERED_SERVICE_PATHS:
                service_lst.append(service)

        for service in service_lst:
            service_parent = service.getparent()
            service_str = le.tostring(service, pretty_print=True)
            pattern = r'\sxmlns[^"]+"[^"]+"'
            service_str = re.sub(pattern, '', service_str.decode('UTF-8'))
            service_parent.replace(service, le.Comment(service_str))

        preserve_the_file_after_patching()
        doc.write(FULL_CONFIG_URI, pretty_print=True, xml_declaration=True, encoding='UTF-8')
    print("OK : Patched the config file.")


def restart_analytics():
    print("\nRunning the restart command : " + RESTART_CMD)
    stream = os.popen(RESTART_CMD)
    output = stream.read()
    print("OK : Restart command completed.")
    return "Successfully started service analytics" in output


def restore_file():
    print("\nRestoring the patched file. "
          "The changes will be preserved in " + BACKUP_FILE_PATH)
    shutil.copyfile(FULL_CONFIG_URI_BACKUP, FULL_CONFIG_URI)
    print("OK : Original file restored.")


def preserve_the_file_after_patching():
    backup_file_name_after_patch = BACKUP_FILE_PATH + CONFIG_FILE + \
                                   "---AFTER_PATCH---" + RPM_VERSION + "-" + RUN_TIME_STAMP + '.backup'
    shutil.copyfile(FULL_CONFIG_URI, backup_file_name_after_patch)
    print("OK : Patched config file backed up as : " + backup_file_name_after_patch)


def get_analytics_rpm_version_string():
    stream = os.popen(RPM_VERSION_CMD)
    output = stream.read()
    print("OK : RPM version : " + output)
    return output.rstrip()


def setup():
    global RPM_VERSION
    RPM_VERSION = get_analytics_rpm_version_string()
    global RUN_TIME_STAMP
    RUN_TIME_STAMP = datetime.datetime.now().strftime("%Y-%b-%d-%H-%M-%S")
    print("OK : Run time stamp : " + RUN_TIME_STAMP)


def main():
    setup()

    vulnerable_before_patch = check_for_open_vulnerabilities()
    if vulnerable_before_patch is False:
        return

    backup_configs()

    patch_configs()

    restart_successful = restart_analytics()

    if not restart_successful:
        print("FAIL : Restart failed, check the analytics logs. \n" + REVERT_CHECK_KB_MANUAL + "\n")
        restore_file()
        return

    vulnerable_after_patch = check_for_open_vulnerabilities()
    if vulnerable_after_patch:
        print(
            "FAIL : Patching was done, but the vulnerabilities are still present. \n"
            + REVERT_CHECK_KB_MANUAL + "\n")
        restore_file()
        return

    print("\n\nSUCCESS : Patching completed. Vulnerabilities are NOT detected.")


if __name__ == "__main__":
    main()
