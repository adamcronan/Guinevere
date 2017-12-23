
## Generate a JSON object of the aggregated assessment information

# Python Imports
import logging, os, json
# My imports
import Print_Banner, DB_Connect, Assessment_Report, Main_Menu
from Guinevere import get_color, get_args

def generate_assessment_json():


    note = get_color('note')
    warn = get_color('warn')
    question = get_color('question')
    args = get_args()

    logging.info('Entering the generate_assessment_json function')
    os.system('clear')
    Print_Banner.print_banner()
    print "Retrieving available assessments..."
    assessment = DB_Connect.get_assessment("the assessment to create a JSON object for")
    Print_Banner.print_banner()
    crosstable = DB_Connect.get_crosstable(assessment)
    vID = Assessment_Report.assessment_vulns(assessment, crosstable)
    os.system('clear')
    Print_Banner.print_banner()
    print "["+note+"]Building JSON object for " + assessment + " Crosstable " + crosstable + "..."
    vuln = Assessment_Report.get_vulns(vID, assessment, crosstable, args)
    rID = Assessment_Report.assessment_report(vuln, args)
    assessment_db = Assessment_Report.get_report(rID, vuln, args)
    engagment_details = DB_Connect.gather_assessment_details(assessment)
    json_dict = {'engagment_details': engagment_details, 'report': assessment_db}
    json_object = json.dumps(json_dict)
    out_dir = Assessment_Report.get_path()
    json_file = os.path.join(out_dir, "Guinevere_" + assessment + "_" + crosstable + ".json")
    with open(json_file, "w") as j:
        j.write(json_object)
    print "["+warn+"]Assessment JSON object saved to: " + json_file
    raw_input("["+question+"]Press enter to continue...")
    Main_Menu.print_main_menu()
