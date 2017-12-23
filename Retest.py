
# Create a retest report for an assessment

# Python Imports
import os, docx
# My Imports
import Print_Banner, DB_Connect, Assessment_Report, Sort_IP
from Guinevere import get_color

def retest(cli_args):
    """Create a report for a retest of an assessment"""

    note = get_color('note')
    warn = get_color('warn')
    info = get_color('info')

    os.system('clear')
    Print_Banner.print_banner()
    print "Retrieving available assessments..."

    # Collect data from the original assessment
    original_assessment = DB_Connect.get_assessment("the original assessment")
    Print_Banner.print_banner()
    original_crosstable = DB_Connect.get_crosstable(original_assessment)
    print "["+note+"]Gathering original assessment vulnerability IDs..."
    original_vID = Assessment_Report.assessment_vulns(original_assessment, original_crosstable)
    print "["+note+"]Gathering original assessment vulnerability dataset..."
    original_vuln = Assessment_Report.get_vulns(original_vID, original_assessment, original_crosstable, cli_args)

    # Collect data from the retest
    retest_assessment = DB_Connect.get_assessment("the retest assessment")
    Print_Banner.print_banner()
    retest_crosstable = DB_Connect.get_crosstable(retest_assessment)
    print "["+note+"]Gathering retest vulnerability IDs..."
    retest_vID = Assessment_Report.assessment_vulns(retest_assessment, retest_crosstable)
    print "["+note+"]Gathering retest vulnerability dataset..."
    retest_vuln = Assessment_Report.get_vulns(retest_vID, retest_assessment, retest_crosstable, cli_args)

    # Create the report stub
    retest_report = docx.Document()
    retest_report.add_heading(original_assessment+' Retest Results')

    retest = {} # Dictionary to hold retest data

    for i in original_vuln:
        if original_vuln[i]['vuln_rating'] is not None and original_vuln[i]['vuln_rating'] is not "Informational":
            retest[i] = {'vuln_id': i, 'vuln_title': original_vuln[i]['vuln_title'], 'vuln_rating': original_vuln[i]['vuln_rating'],
                         'total_orig': len(set(original_vuln[i]['vuln_hosts']))}
            if i in retest_vuln:
                o = set(original_vuln[i]['vuln_hosts']) #Original
                r = set(retest_vuln[i]['vuln_hosts'])   #Retest
                l = o - r                               #Leftover, fixed hosts
                b = []  # List of hosts from the original retest that are found in the retest

                for x in o: # For each host in the original assessment, check to see if it is in the retest assessment
                    if x in r:
                        b.append(x)
                if len(b) == 0:
                    print "\t["+note+"]" + original_vuln[i]['vuln_title'] + " - Remediated"
                    retest[i].update({'status': 'Remediated'})
                elif len(b) == len(o):
                    print "\t["+warn+"]" + original_vuln[i]['vuln_title'] + " - Not Remediated"
                    retest[i].update({'status': 'Not Remediated'})
                    retest[i].update({'v_hosts': o}) #Hosts Still Vulnerable, contributed by Zach
                else:
                    print "\t["+info+"]" + original_vuln[i]['vuln_title'] + \
                          " - Partially Remediated (Still vulnerable: " + str(len(b)) + ")"
                    retest[i].update({'status': 'Partially Remediated'})
                    retest[i].update({'v_hosts': b})#Hosts still vulnerable
                    retest[i].update({'f_hosts': l}) #Fixed hosts
            else:
                print "\t["+note+"]" + original_vuln[i]['vuln_title'] + " - Remediated"
                retest[i].update({'status': 'Remediated'})

    # Build Status Table
    retest_report.add_heading('Vulnerability Status')
    status_table = retest_report.add_table(rows=1, cols=3)
    status_table.style = 'Medium Grid 1 Accent 1'
    hdr_cells = status_table.rows[0].cells
    hdr_cells[0].text = 'Severity'
    hdr_cells[1].text = 'Vulnerability'
    hdr_cells[2].text = 'Status'

    # Add Critical first
    for i in retest:
        if retest[i]['vuln_rating'] is 'Critical':
            row_cells = status_table.add_row().cells
            row_cells[0].text = retest[i]['vuln_rating']
            row_cells[1].text = retest[i]['vuln_title']
            row_cells[2].text = retest[i]['status']

    # Add High second
    for i in retest:
        if retest[i]['vuln_rating'] is 'High':
            row_cells = status_table.add_row().cells
            row_cells[0].text = retest[i]['vuln_rating']
            row_cells[1].text = retest[i]['vuln_title']
            row_cells[2].text = retest[i]['status']

    # Add Medium third
    for i in retest:
        if retest[i]['vuln_rating'] is 'Medium':
            row_cells = status_table.add_row().cells
            row_cells[0].text = retest[i]['vuln_rating']
            row_cells[1].text = retest[i]['vuln_title']
            row_cells[2].text = retest[i]['status']

    # Add Low last
    for i in retest:
        if retest[i]['vuln_rating'] is 'Low':
            row_cells = status_table.add_row().cells
            row_cells[0].text = retest[i]['vuln_rating']
            row_cells[1].text = retest[i]['vuln_title']
            row_cells[2].text = retest[i]['status']

    # Build Still Vulnerable Hosts Table
    retest_report.add_heading('Hosts Still Vulnerable')
    vulnerable_table = retest_report.add_table(rows=1, cols=3)
    vulnerable_table.style = 'Medium Grid 1 Accent 1'
    hdr_cells = vulnerable_table.rows[0].cells
    hdr_cells[0].text = 'Severity'
    hdr_cells[1].text = 'Vulnerability'
    hdr_cells[2].text = 'Hosts'

    #Criticals
    for i in retest:
        # "and retest[i]['vuln_rating'] is not 'Informational' and len(retest[i]['v_hosts']) > 0" Contriubted by Zach
        if 'v_hosts' in retest[i] and retest[i]['vuln_rating'] is not 'Informational' and len(retest[i]['v_hosts']) > 0:
            if retest[i]['vuln_rating'] is 'Critical':
                row_cells = vulnerable_table.add_row().cells
                row_cells[0].text = retest[i]['vuln_rating']
                row_cells[1].text = retest[i]['vuln_title']
                hosts = []
                for h in retest[i]['v_hosts']:
                    hosts.append(h[0])
                row_cells[2].text = ((str(Sort_IP.ip_sort_list(hosts)).replace("'", "")).lstrip("[")).rstrip("]")

    #Highs
    for i in retest:
        # "and retest[i]['vuln_rating'] is not 'Informational' and len(retest[i]['v_hosts']) > 0" Contriubted by Zach
        if 'v_hosts' in retest[i] and retest[i]['vuln_rating'] is not 'Informational' and len(retest[i]['v_hosts']) > 0:
            if retest[i]['vuln_rating'] is 'High':
                row_cells = vulnerable_table.add_row().cells
                row_cells[0].text = retest[i]['vuln_rating']
                row_cells[1].text = retest[i]['vuln_title']
                hosts = []
                for h in retest[i]['v_hosts']:
                    hosts.append(h[0])
                row_cells[2].text = ((str(Sort_IP.ip_sort_list(hosts)).replace("'", "")).lstrip("[")).rstrip("]")

    #Mediums
    for i in retest:
        # "and retest[i]['vuln_rating'] is not 'Informational' and len(retest[i]['v_hosts']) > 0" Contriubted by Zach
        if 'v_hosts' in retest[i] and retest[i]['vuln_rating'] is not 'Informational' and len(retest[i]['v_hosts']) > 0:
            if retest[i]['vuln_rating'] is 'Medium':
                row_cells = vulnerable_table.add_row().cells
                row_cells[0].text = retest[i]['vuln_rating']
                row_cells[1].text = retest[i]['vuln_title']
                hosts = []
                for h in retest[i]['v_hosts']:
                    hosts.append(h[0])
                row_cells[2].text = ((str(Sort_IP.ip_sort_list(hosts)).replace("'", "")).lstrip("[")).rstrip("]")

    #Lows
    for i in retest:
        # "and retest[i]['vuln_rating'] is not 'Informational' and len(retest[i]['v_hosts']) > 0" Contriubted by Zach
        if 'v_hosts' in retest[i] and retest[i]['vuln_rating'] is not 'Informational' and len(retest[i]['v_hosts']) > 0:
            if retest[i]['vuln_rating'] is 'Low':
                row_cells = vulnerable_table.add_row().cells
                row_cells[0].text = retest[i]['vuln_rating']
                row_cells[1].text = retest[i]['vuln_title']
                hosts = []
                for h in retest[i]['v_hosts']:
                    hosts.append(h[0])
                row_cells[2].text = ((str(Sort_IP.ip_sort_list(hosts)).replace("'", "")).lstrip("[")).rstrip("]")


    # Build stats table
    o_total_c = 0   # Original Total Critical
    r_total_c = 0   # Retest Total Critical
    o_total_h = 0
    r_total_h = 0
    o_total_m = 0
    r_total_m = 0
    o_total_l = 0
    r_total_l = 0
    for i in retest:
        # Critical Vulnerabilities
        if retest[i]['vuln_rating'] is 'Critical':
            o_total_c += retest[i]['total_orig']
            if 'v_hosts' in retest[i]:
                r_total_c += len(retest[i]['v_hosts'])
        # High Vulnerabilities
        if retest[i]['vuln_rating'] is 'High':
            o_total_h += retest[i]['total_orig']
            if 'v_hosts' in retest[i]:
                r_total_h += len(retest[i]['v_hosts'])
        # Medium Vulnerabilities
        if retest[i]['vuln_rating'] is 'Medium':
            o_total_m += retest[i]['total_orig']
            if 'v_hosts' in retest[i]:
                r_total_m += len(retest[i]['v_hosts'])
        # Low Vulnerabilities
        if retest[i]['vuln_rating'] is 'Low':
            o_total_l += retest[i]['total_orig']
            if 'v_hosts' in retest[i]:
                r_total_l += len(retest[i]['v_hosts'])

    s = "The original security assessment identified (" + str(o_total_c) + ") critical-severity, (" \
        + str(o_total_h) + ") high-severity, (" + str(o_total_m) + ") medium-severity, and (" \
        + str(o_total_l) + ") low-severity vulnerabilities."

    # Setup Table
    retest_report.add_heading('Retest Statistics')
    retest_report.add_paragraph(s)
    stats_table = retest_report.add_table(rows=1, cols=5)
    stats_table.style = 'Medium Grid 1 Accent 1'
    hdr_cells = stats_table.rows[0].cells
    hdr_cells[0].text = ''
    hdr_cells[1].text = 'Critical'
    hdr_cells[2].text = 'High'
    hdr_cells[3].text = 'Medium'
    hdr_cells[4].text = 'Low'
    # Original Assessment Numbers
    row_cells = stats_table.add_row().cells
    row_cells[0].text = 'Original'
    row_cells[1].text = str(o_total_c)
    row_cells[2].text = str(o_total_h)
    row_cells[3].text = str(o_total_m)
    row_cells[4].text = str(o_total_l)

    # Retest Assessment Numbers
    row_cells = stats_table.add_row().cells
    row_cells[0].text = 'Retest'
    row_cells[1].text = str(r_total_c)
    row_cells[2].text = str(r_total_h)
    row_cells[3].text = str(r_total_m)
    row_cells[4].text = str(r_total_l)

    Assessment_Report.save_report(retest_report, retest_assessment)