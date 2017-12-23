#!/usr/bin/python
#!/usr/bin/env python

"""Guinevere is a tool used to automate security assessment reporting"""

# Python Imports
import os, argparse, logging, readline, sys
# My Imports
import Main_Menu

#Requires MySQL driver, python-mysqldb for Linux. Seems to be installed in Kali
#Requires python-docx library, apt-get update; apt-get install -y python-pip mysql-client;pip install python-docx
#Requires cvsss library; pip install cvss
### OSX Install Notes:
# sudo su -
# export CFLAGS=-Qunused-arguments
# export CPPFLAGS=-Qunused-arguments
# pip install mysql-python
# pip install python-docx
# pip install netaddr

#################################################
#           Guinevere Variables                 #
#################################################
__author__ = "Russel Van Tuyl"
__license__ = "GPL"
__version__ = "1.4.1"
__maintainer__ = "Russel Van Tuyl"
__email__ = "Russel.VanTuyl@gmail.com"
__status__ = "Development"
G_root = os.path.dirname(os.path.realpath(__file__))
readline.parse_and_bind('tab: complete')
readline.set_completer_delims('\t')
# logging.basicConfig(stream=sys.stdout, format='%(asctime)s\t%(levelname)s\t%(message)s',
                    # datefmt='%Y-%m-%d %I:%M:%S %p', level=logging.DEBUG)  # Log to STDOUT
logging.basicConfig(filename=os.path.join(G_root, 'Guinevere.log'), format='%(asctime)s\t%(levelname)s\t%(message)s',
                    datefmt='%Y-%m-%d %I:%M:%S %p', level=logging.DEBUG)  # Log to File
#################################################
#CHANGE TO MATCH YOUR DATABASE
g_ip = "127.0.0.1"          # Database IP address
g_p = 3306                  # Database Port
g_user = "gauntlet"             # Database Username
g_pass = "password"         # Database Password
#################################################
#                   COLORS                      #
#################################################
note = "\033[0;0;33m-\033[0m"
warn = "\033[0;0;31m!\033[0m"
info = "\033[0;0;36mi\033[0m"
question = "\033[0;0;37m?\033[0m"
debug = "\033[0;0;31m[DEBUG]\033[0m"

#Parse command line arguments
parser = argparse.ArgumentParser()
parser.add_argument('-H', '--db-host', type=str, default=g_ip, help="MySQL Database Host. Default set in script")
parser.add_argument('-U', '--db-user', type=str, default=g_user, help="MySQL Database Username. Default set in script")
parser.add_argument('-P', '--db-pass', type=str, default=g_pass, help="MySQL Database Password. Default set in script")
parser.add_argument('-p', '--db-port', type=str, default=g_p, help="MySQL Database Port. Default set in script")
parser.add_argument('-l', '--lines', type=int, default=10, help="Number of lines to display when selecting an "
                                                                "engagement. Default is 10")
parser.add_argument('-A', '--all-vulns', action='store_true', default=False, help="Include all vulnerability headings "
                                                                                  "when there are no associated report "
                                                                                  "narratives")
parser.add_argument('-V', '--all-verb', action='store_true', default=False, help="Include all vureto vulnerability "
                                                                                 "verbiage when there are no "
                                                                                 "associated report narratives")
parser.add_argument('--ports', action='store_false', default=True, help="Exclude port information vulnerability "
                                                                        "write-up portion of the report")
parser.add_argument('--cvss', action='store_false', default=True, help="Exclude CVSS scores from vulnerability titles")
parser.add_argument('-sC', action='store_false', default=True, help="Exclude Critical-Severity Vulnerabilities")
parser.add_argument('-sH', action='store_false', default=True, help="Exclude High-Severity Vulnerabilities")
parser.add_argument('-sM', action='store_false', default=True, help="Exclude Medium-Severity Vulnerabilities")
parser.add_argument('-sL', action='store_true', default=False, help="Include Low-Severity Vulnerabilities")
parser.add_argument('-sI', action='store_true', default=False, help="Include Informational-Severity Vulnerabilities")
parser.add_argument('-aD', '--assessment-date', action='store_true', default=False, help='Include the date when '
                                                                                         'selecting an assessment '
                                                                                         'to report on')
parser.add_argument('-T', '--tool-output', action='store_false', default=True, help="Exclude Tool Output When Printing "
                                                                                    "G-Checklist")
parser.add_argument('--debug', action='store_true', default=False, help="Enable debug output to console")
args = parser.parse_args()

def get_Guinevere_variables(variable_name):
    if variable_name == 'maintainer':
        return __maintainer__
    if variable_name == 'author':
        return __author__
    if variable_name == 'email':
        return __email__
    if variable_name == 'version':
        return __version__

def get_G_root():
    return G_root

def get_args():
    return args

def get_color(level):
    if level == 'note':
        return note
    elif level == 'warn':
        return warn
    elif level == 'info':
        return info
    elif level == 'question':
        return question
    elif level == 'debug':
        return debug
    else:
        return info


if args.debug:
    print "\n["+warn+"]Debug output enabled"
    logging.basicConfig(stream=sys.stdout, format='%(asctime)s\t%(levelname)s\t%(message)s',
                        datefmt='%Y-%m-%d %I:%M:%S %p', level=logging.DEBUG)  # Log to STDOUT
    raw_input("Press enter to continue...")


if __name__ == '__main__':
    try:
        Main_Menu.print_main_menu()
    except KeyboardInterrupt:
        logging.info('User Interrupt! Quitting')
        print "\n["+warn+"]User Interrupt! Quitting...."
    except SystemExit:
        pass
    except:
        print "\n["+warn+"]Please report this error to " + __maintainer__ + " by email at: "+ __email__
        raise
