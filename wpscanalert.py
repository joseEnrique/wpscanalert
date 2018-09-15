#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
import os
import re
import traceback
import sys
import subprocess
from subprocess import check_output, CalledProcessError, STDOUT
from datetime import datetime
from case import sendtoHIVE
import mongo

# General Options
wpscan_dir              = os.getenv('WPSCAN_DIR',r'/root/wpscan/wpscan')
wp_site                =  os.getenv('WPSCAN_URL',r'http://localhost/')
false_positive_strings  = [ 'XML-RPC', 'GHOST vulnerability' ]
# Log file
log_file                = r'./wpwatcher.log'


# Update WPScan from github
def update_wpscan():
    print "[INFO] Updating WPScan"
    os.chdir(wpscan_dir)
    try:
        result = check_output(r'./wpscan.rb --batch --update', stderr=STDOUT, shell=True, universal_newlines=True)
        print result
    except CalledProcessError as exc:
        print "[ERROR]", exc.returncode, exc.output


# Run WPScan on defined domains
def run_scan():
    print "[INFO] Starting scans on configured sites"
    os.chdir(wpscan_dir)
    result = ""
    # Scan ----------------------------------------------------------------
    p = subprocess.Popen(r'./wpscan.rb --batch --url %s' % wp_site, stdout=subprocess.PIPE, shell=True, universal_newlines=True)
    print "[INFO] Scanning '%s'" % wp_site
    result =  p.communicate()
    # Parse the results ---------------------------------------------------
    alerts = parse_results(result[0])
    for alert in alerts:
        print alert
        title = re.compile("\[!\] Title:(.+) -").search(alert)
        title = title.group(0)[4:-1]
        db = mongo.get_db()
        # if not it exists, create it and send it
        if not mongo.get_vulnerability(db,wp_site,title):
            mongo.add_vulnerability(db,wp_site,title)
            sendtoHIVE("[WORDPRESS] "+title,alert,wp_site)

# Is the line defined as false positive
def is_false_positive(string):
    # False Positive Detection
    for fp_string in false_positive_strings:
        if fp_string in string:
            # print fp_string, string
            return 1
    return 0

def get_timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def parse_results(results):
    warnings = []
    alerts = []
    realalerts = []
    warning_on = False
    alert_on = False
    last_message = ""
    warning = ""
    alert = ""
    # Parse the lines
    for line in results.splitlines():
        # Remove colorization

        line = re.sub(r'(\x1b|\[[0-9][0-9]?m)','',line)
        # Empty line = end of message
        if line == "" or line.startswith("[+]"):
            if warning_on:
                if not is_false_positive(warning):
                    warnings.append(warning)
                warning_on = False
            if alert_on:
                if not is_false_positive(alert):
                    alerts.append(alert)
                alert_on = False
        # Add to warning/alert
        if warning_on:
            warning += " / %s" % line.lstrip(" ")
        if alert_on:
            alert += " / %s" % line.lstrip(" ")
        # Start Warning/Alert
        if line.startswith("[i]"):
            # Warning message
            warning = "%s / %s" % ( last_message, line )
            warning_on = True
        if line.startswith("[!]"):
            # Warning message
            alert = line
            alert_on = True

        # Store lase message
        last_message = line
    
    for alert in alerts:
        if "Title:" in alert:
            realalerts.append(alert)
    return  realalerts


if __name__ == '__main__':
    update_wpscan()
    # Run Scan
    run_scan()