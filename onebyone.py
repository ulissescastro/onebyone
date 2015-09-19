#!/usr/bin/env python
import csv
import sys
import os
import socket
import re
import subprocess, shlex
import time
import random
from pprint import pprint


class b:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def check_boolean(string):
    if 'true' in string.lower():
        return True

    return False


def str_to_list(string, sep):
    return string.replace(' ', '').split(sep)


def list_to_str(str_list):
    return re.sub('[ \[\]\']', '', str_list)


def cve_parser(allitems_csv_file):
    # download from
    # http://cve.mitre.org/data/downloads/allitems.csv
    counter = 0
    cve_info = {}
    
    reader = csv.reader(open(allitems_csv_file, 'rb'))
    for row in reader:
        # skip top 10 headers
        # "Name","Status","Description","References","Phase","Votes","Comments"
        if counter < 10:
            counter += 1
            continue
        
        cve = row[0]
        if not cve_info.has_key(cve):
            cve_info[cve] = {}

        
        cve_info[cve]['status'] = row[1]
        cve_info[cve]['description'] = row[2]
        # get 5 sample references
        pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        cve_info[cve]['references'] = re.findall(pattern, row[3])
        if len(cve_info[cve]['references']) > 5:
            cve_info[cve]['references'] = random.sample(cve_info[cve]['references'], 5) 

        cve_info[cve]['phase'] = row[4]
        cve_info[cve]['votes'] = row[5]
        cve_info[cve]['comments'] = row[6]

    return cve_info


def carrier_parser(csv_file):
    counter = 0
    host_info = {}
    
    reader = csv.reader(open(csv_file, 'rb'))
    for row in reader:
        # skip headers
        # Priority,Risk,Tags,Notes,IP,Protocol,Port,Service Protocol,Vuln Code,Vuln Name,CVSS Score,CVE,Version Based,Evidence
        if counter == 0:
            counter += 1
            continue
        
        vuln_code = str(row[8])

        if not host_info.has_key(vuln_code):
            host_info[vuln_code] = {}

        host_info[vuln_code]['priority'] = int(row[0])
        host_info[vuln_code]['risk'] = int(row[1])
        host_info[vuln_code]['tags_list'] = str(row[2]).strip().split()
        host_info[vuln_code]['notes_list'] = str(row[3]).strip().split()
        host_info[vuln_code]['hosts_list'] = str(row[4]).replace(' ', '').split(',')
        host_info[vuln_code]['protocol_list'] = str(row[5]).replace(' ', '').split(',')
        host_info[vuln_code]['port_list'] = str(row[6]).replace(' ', '').split(',')
        host_info[vuln_code]['service_list'] = str(row[7]).strip().split()
        host_info[vuln_code]['vuln_name'] = str(row[9])
        host_info[vuln_code]['cvss_score'] = float(row[10])
        host_info[vuln_code]['cve_list'] = str(row[11]).strip().split()
        host_info[vuln_code]['version_based'] = check_boolean(str(row[12]).strip())
        host_info[vuln_code]['evidence'] = str(row[13])

    return host_info


def check_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(3.0)
    try:
        sock.connect((host, int(port)))
        return True
    except Exception:
        pass

    return False


def cve_search(all_items_cve, cve_id):
    urls = ""
    for ref in all_items_cve[cve_id]['references']:
        urls += "%s\n" % ref

    return all_items_cve[cve_id]['description'], urls


def manual_check_helper(all_items_cve, sorted_findings, cvss_treshold):
    report = open('./report.txt', 'w')
    host_info = carrier_parser(sorted_findings)
    total = len(host_info)
    remaining = 0
    for vuln_code, info in host_info.iteritems():
        if info['cvss_score'] >= float(cvss_treshold):
            remaining += 1

    for vuln_code, info in host_info.iteritems():
        if info['cvss_score'] >= float(cvss_treshold):
            hosts = list_to_str(str(info['hosts_list']))
            services = list_to_str(str(info['service_list']))
            output = "REMAINING: %s%s/%s%s    " % (b.BOLD, remaining, total, b.ENDC)
            output += "CODE: %s%s%s   " % (b.BOLD, vuln_code, b.ENDC)
            output += "VERSION BASED: %s%s%s    " % (b.BOLD, info['version_based'], b.ENDC)
            output += "CVSS: %s%s%s%s%s\n" % (b.BOLD, b.FAIL, info['cvss_score'], b.ENDC, b.ENDC)
            output += "NAME: %s%s%s\n" % (b.WARNING, info['vuln_name'], b.ENDC)
            output += "HOSTS: %s\n" % hosts
            cve_list = info['cve_list']
            if len(cve_list) >= 3:
                cve_list = random.sample(info['cve_list'], 3)
            
            for cve in cve_list:
                output += "CVE: %s%s%s\n" % (b.WARNING, cve, b.ENDC)
                description, references = cve_search(all_items_cve, cve)
                output += "%s\n" % description

            output += "\n"
            for host in info['hosts_list']:
                output += "HOST: %s%s%s\n" % (b.BOLD, host, b.ENDC)
                for port in info['port_list']:
                    if port:
                        print "%s%s %s%s" % (b.WARNING, host, port, b.ENDC)
                        if check_port(host, port):
                            output += "\t[%sOK%s] %s:%s\n" % (b.OKGREEN, b.ENDC, host, port)
                        else:
                            output += "\t[%sFAIL%s] %s:%s\n" % (b.FAIL, b.ENDC, host, port)
            
            if info['evidence']:
                output += "\nEVIDENCE(s):\n%s\n" % info['evidence'].replace('; ', '\n')

            if references:
                output += "\nREFERENCE(s):\n%s\n" % references

            notes = ""
            if info['notes_list']:
                for note in info['notes_list']:
                    notes += "%s\n" % note

            if notes:
                output += "NOTE(s):\n%s" % notes

            os.system('clear')
            print output
            status = raw_input('vulnerable? [y/N] > ')
            if status == 'y':
                for host in info['hosts_list']:
                    txt = '%s %s\n' % (vuln_code, host)
                    report.write(txt)                

            os.system('clear')
            remaining -= 1

    return

if __name__ == '__main__':
    all_items_cve = cve_parser('./cve/allitems.csv')
    # pprint(all_items_cve)
    # sys.exit(0)
    manual_check_helper(all_items_cve, sys.argv[1], sys.argv[2])

