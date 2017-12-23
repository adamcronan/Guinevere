
# Dump a sql file of information for a given assessment

# Python Imports
import subprocess, time, platform, os
# My Imports
import DB_Connect, Assessment_Report, Print_Banner, Main_Menu
from Guinevere import get_color

def sql_dump(cli_args):
    """Use mysqldump to export an assessment to a .sql file"""

    warn = get_color('warn')
    question = get_color('question')

    #Find the script location and set the mysqldump executable
    #Will implement functionality in the future
    script_path = os.path.dirname(os.path.realpath(__file__))
    bin_path = os.path.join(script_path, 'bin')
    #Determine the operating system
    operating_system = platform.platform()
    if 'Windows' in operating_system:
        ext = '.exe'
    elif 'Linux' in operating_system:
        ext = '.bin'
    else:
        ext = '.nothing'
    mysqldump = "mysqldump"
    if os.path.isdir(bin_path) and os.path.exists(bin_path+'mysqldump.'+ext):
        mysqldump = bin_path+'mysqldump.'+ext

    assessment = DB_Connect.get_assessment("the assessment to backup")
    os.system('clear')
    Print_Banner.print_banner()
    output_path = Assessment_Report.get_path()
    date_time = time.strftime('%m%d%Y-%H%M%S')
    try:
        sql_file = open(os.path.join(output_path, assessment+"_"+date_time+".sql"), "w")
        subprocess.call([mysqldump, "--host="+cli_args.db_host, "-u", cli_args.db_user, "-p"+cli_args.db_pass, "gauntlet_"+assessment], stdout=sql_file)
        #os.system(mysqldump+" --host="+args.db_host+" -u "+args.db_user+" -p"+args.db_pass+" gauntlet_"+assessment+" > "+sql_file)
        print "["+warn+"]SQL file saved to: " + os.path.join(output_path, assessment+"_"+date_time+".sql")
    except OSError:
        print "["+warn+"]mysqldump is likely not in your path, please add it and try again"
        raise
    except:
        raise #Just use for debug
    raw_input("["+question+"]Press enter to continue...")
    Main_Menu.print_main_menu()