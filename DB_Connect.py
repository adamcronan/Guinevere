
## Functions required for interfacing with Gauntlet Database

# Python Imports
import MySQLdb, logging, os
from warnings import filterwarnings, resetwarnings
# My Imports
import Print_Banner
# Unsure if this is a good way to do this
#TODO refactor functions that need access to args to accept them as parameters
from Guinevere import get_args, get_color

args = get_args()

def ignore_mysql_warnings():
    filterwarnings('ignore', category=MySQLdb.Warning)  # Disable MySQL Warnings

def dont_ignore_mysql_warnings():
    resetwarnings()  # Re-enable MySQL Warnings

# Takes in the name of a database in our mysql instance, returns a connection to that database
def db_connect(database_name, cli_args):
    db = MySQLdb.connect(host=cli_args.db_host, user=cli_args.db_user, passwd=cli_args.db_pass, port=cli_args.db_port, db=database_name)
    return db

# These functions take in a database connection created in db_connect, create a cursor, and perform a query
# Returns data selected from the database and closes the connection
def db_interact_fetchone(database_connection, query):
    temp_cursor = database_connection.cursor()
    temp_cursor.execute(query)
    temp_data_container = temp_cursor.fetchone()
    temp_cursor.close()
    return temp_data_container

def db_interact_fetchmany(database_connection, query):
    temp_cursor = database_connection.cursor()
    temp_cursor.execute(query)
    temp_data_container = temp_cursor.fetchmany()
    temp_cursor.close()
    return temp_data_container

def db_interact_fetchall(database_connection, query):
    temp_cursor = database_connection.cursor()
    temp_cursor.execute(query)
    temp_data_container = temp_cursor.fetchall()
    temp_cursor.close()
    return temp_data_container

def db_query(q, assessment):
    """General use function used for querying the assessment database"""

    if assessment == "GauntletData":
        assessment2 = assessment
    else:
        assessment2 = "gauntlet_" + assessment

    db = db_connect(assessment2, args)
    try:
        gauntlet=db.cursor()
        gauntlet.execute(q)
        recordset = gauntlet.fetchall()
        gauntlet.close()
        return recordset
    except:
        print "There was an error performing the following query: "
        print q

def get_assessment(info_string_for_user):
    """Connects to the assessment database and prompts user to select an engagement"""

    logging.info('Entering the get_assessment function')
    db = MySQLdb.connect(host=args.db_host, user=args.db_user, passwd=args.db_pass, port=args.db_port)
    gauntlet=db.cursor()
    gauntlet.execute("""show databases""")
    all_available_databases = gauntlet.fetchall()
    gauntlet.close()
    discovered_gauntlet_databases = []
    os.system('clear')
    Print_Banner.print_banner()

    # number of databases to print at a time
    database_print_limit_counter = args.lines

    # add all databases that start with 'gauntlet_' to a list
    for discovered_db in all_available_databases:
        if discovered_db[0].startswith('gauntlet'):
            discovered_gauntlet_databases.append(discovered_db[0].replace("gauntlet_", ''))

    #Print engagements to screen and have user choose one
    # Counter for number of engagements printed to the screen
    printed_engagement_counter = 0
    z = False
    # Counter for the number of engagements to display at a time
    eng_display_limit_counter = database_print_limit_counter
    while z != True:
        if (printed_engagement_counter <= eng_display_limit_counter) and (printed_engagement_counter < len(discovered_gauntlet_databases)):
            if args.assessment_date:
                SDate = db_query('select value  FROM engagement_details WHERE `key`="Start Date"', discovered_gauntlet_databases[printed_engagement_counter])
                if SDate is not None:
                    print "[" + str(printed_engagement_counter) + "]" + discovered_gauntlet_databases[printed_engagement_counter] + "\t" + SDate[0][0]
            else:
                print "[" + str(printed_engagement_counter) + "] " + discovered_gauntlet_databases[printed_engagement_counter]
            printed_engagement_counter += 1
        else:
            print "[99] More..."
            question = get_color('question')
            user_selection_string = raw_input("\n[" + question +"]Please select " + info_string_for_user + ": ")
            try:
                if ((user_selection_string == "99") or (user_selection_string == "")):
                    if printed_engagement_counter == len(discovered_gauntlet_databases):
                        printed_engagement_counter = 0
                        eng_display_limit_counter = database_print_limit_counter
                    else:
                        eng_display_limit_counter = eng_display_limit_counter + database_print_limit_counter
                    os.system('clear')
                    Print_Banner.print_banner()
                elif user_selection_string == "Q" or user_selection_string == "q":
                    exit()
                elif discovered_gauntlet_databases[int(user_selection_string)]:
                    z = True
                else:
                    pass
            except:
                    warn = get_color('warn')
                    os.system('clear')
                    Print_Banner.print_banner()
                    print "["+warn+"]ERROR: " + user_selection_string + " is not a valid option. Try again"
                    printed_engagement_counter = 0
                    eng_display_limit_counter = database_print_limit_counter
    os.system('clear')
    logging.info(discovered_gauntlet_databases[int(user_selection_string)] + " assessment selected by user")

    return discovered_gauntlet_databases[int(user_selection_string)]

def gather_assessment_details(assessment):
    """Gather assessment details from Gauntlet and create a dictionary"""

    logging.info('Entering the gather_assessment_details function')
    engagement = db_query("""SELECT value FROM gauntlet_%s.engagement_details WHERE
                          engagement_details.key = 'Engagement Task 1'""" % (assessment), assessment)#[0][0]
    # In the case that the engagement type is not found, give it a value of "Not Found"
    if engagement == ():
        engagement = "Not Found"
    else:
        engagement = engagement[0][0]
    start_date = db_query("""SELECT value FROM gauntlet_%s.engagement_details WHERE
                          engagement_details.key = 'Start Date'""" % (assessment), assessment)[0][0]
    end_date = db_query("""SELECT value FROM gauntlet_%s.engagement_details WHERE
                          engagement_details.key = 'End Date'""" % (assessment), assessment)[0][0]
    analyst = db_query("""SELECT value FROM gauntlet_%s.engagement_details WHERE
                          engagement_details.key = 'Analyst 1'""" % (assessment), assessment)[0][0]

    details = {'engagment_type': engagement, 'start_date': start_date, 'stop_date': end_date, 'analyst': analyst}
    return details

def get_crosstable(assessment):
    """Select the which assessment crosstable to use"""

    logging.info('Entering the get_crosstable function')
    chosen_crosstable = ""
    list_of_crosstables = ()
    tries = 0
    #Find all the crosstables for the assessment
    while not list_of_crosstables:
        try:
            if tries < 100:
                q = """SELECT DISTINCT table_id from cross_data_nva"""
                list_of_crosstables = db_query(q, assessment)
            else:
                print "Its broken try again"
                break
        except:
            tries = tries+1

    while not chosen_crosstable:

        # If there is more than 1 crosstable, have the user choose
        if len(list_of_crosstables) > 1:
            list_number = 0
            for crosstable in list_of_crosstables:
                print "[" + str(list_number) + "]",crosstable[0]
                list_number += 1
            try:
                user_choice = raw_input("\nWhich Crosstable would you like to use: ")
                chosen_crosstable = list_of_crosstables[int(user_choice)]
            except:
                warn = get_color('warn')
                os.system('clear')
                Print_Banner.print_banner()
                print "["+warn+"]Error: please try again"

        # Otherwise choose for the user
        else:
            chosen_crosstable = list_of_crosstables[0]

    os.system('clear')
    Print_Banner.print_banner()
    logging.info(str(chosen_crosstable[0]) + " crosstable selected")
    return chosen_crosstable[0]