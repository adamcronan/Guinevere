
## Add new information to Gauntlet Database

# Python Imports
import os
# My Imports
import DB_Connect, Print_Banner, Main_Menu
from Guinevere import get_color, get_Guinevere_variables

def patch_gauntlet(cli_args):

    __maintainer__ = get_Guinevere_variables('maintainer')
    __email__ = get_Guinevere_variables('email')
    warn = get_color('warn')
    question = get_color('question')
    note = get_color('note')

    print "Nothing to test right now"
    db = DB_Connect.db_connect('GauntletData', cli_args)

    create_table = """
        CREATE TABLE report (
            report_id integer NOT NULL AUTO_INCREMENT,
            title character varying(255) NOT NULL DEFAULT '',
            identification blob,
            explanation blob,
            impact blob,
            recommendation blob,
            status ENUM('NEW','MODIFIED','ACCEPTED','MARKED','DELETED') NOT NULL,
            owner character varying(255) NOT NULL DEFAULT '',
            PRIMARY KEY (report_id)
        );"""
    mod_report = """ALTER TABLE report AUTO_INCREMENT = 50000;"""
    mod_vuln_1 = """ALTER TABLE vulns ADD report_id int;"""
    mod_vuln_2 = """ALTER TABLE vulns ADD FOREIGN KEY (report_id) REFERENCES report(report_id);"""

    os.system('clear')
    Print_Banner.print_banner()
    print """["""+warn+"""]Please make sure you have previously selected "(Re-)Initialize Server" in Gauntlet."""
    raw_input("["+question+"]Press enter to continue...")
    try:
        gauntlet = db.cursor()
        gauntlet.execute(create_table)
        gauntlet.execute(mod_report)
        gauntlet.execute(mod_vuln_1)
        gauntlet.execute(mod_vuln_2)
        gauntlet.close()
    except:
        print "\n["+warn+"]Please report this error to " + __maintainer__ + " by email at: " + __email__
        raise
    Main_Menu.print_main_menu()

    print "["+note+"]You can now upload a new master dataset to Gauntlet"
    Main_Menu.print_main_menu()