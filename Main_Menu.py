# Python Imports
import logging, os
# My Imports
import Assessment_JSON, Assessment_Report, Retest, Export_Assessment
import Patch_Gauntlet, Pentest_Checklist, Print_Banner
from Guinevere import get_color, get_args

args = get_args()

def enter_assessment_report_function():
    Assessment_Report.generate_assessment_report(args)

def sql_dump():
    Export_Assessment.sql_dump(args)

def retest():
    Retest.retest(args)

def patch_gauntlet():
    Patch_Gauntlet.patch_gauntlet(args)

def pentest_checklist():
    Pentest_Checklist.generate_pentest_checklist()

def generate_assessment_json():
    Assessment_JSON.generate_assessment_json()

def print_main_menu():
    """Display the main menu"""

    logging.info('Entered into main_menu function')
    i = None
    valid_options = {1: enter_assessment_report_function,
                     2: sql_dump,
                     3: retest,
                     4: patch_gauntlet,
                     5: pentest_checklist,
                     6: generate_assessment_json,
                     7: exit,
    }
    os.system('clear')
    Print_Banner.print_banner()
    try:
        while i is None:
            print "\t\t\t\033[0;0;37mGUINEVERE MAIN MENU\033[0m\n"
            print "[1]Generate Assessment Report"
            print "[2]Export Assessment"
            print "[3]Generate Retest Report"
            print "[4]Patch Gauntled Database"
            print "[5]Generate Pentest Checklist"
            print "[6]Generate Assessment JSON File"
            print "[7]Exit"
            i = raw_input("\nWhat would you like to do: ")
            if int(i) in valid_options:
                valid_options[int(i)]()
            else:
                os.system('clear')
                Print_Banner.print_banner()
                warn = get_color('warn')
                print "["+warn+"]" + str(i) + " is not a valid option, please try again: "
                i = None
    except ValueError:
        print_main_menu()
