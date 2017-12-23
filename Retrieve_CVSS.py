# Python Imports
import logging
from cvss import CVSS2
# My Imports
import DB_Connect

def get_cvss(gnaat_id, version=2):
    """Get a CVSS object using the gnaat_id from the vulns table in the GauntletData database"""

    logging.info('Entered into get_cvss function')

    cvss_info_dictionary = DB_Connect.db_query("SELECT DISTINCT `cvss_access_vector`, `cvss_access_complexity`, `cvss_authentication`, "
                 "`cvss_confidentiality_impact`, `cvss_integrity_impact`, `cvss_availability_impact`, "
                 "`cvss_exploitability`, `cvss_remediation_level`, `cvss_report_confidence` FROM "
                 "vulns WHERE gnaat_id='%s';" % gnaat_id, "GauntletData")

    AV = None   # Access Vector
    AC = None   # Access Complexity
    Au = None   # Authentication
    C = None    # Confidentiality
    I = None    # Integrity
    A = None    # Availability
    E = None    # Exploitability
    RL = None   # Remediation Level
    RC = None   # Report Confidence

    # Access Vector
    if cvss_info_dictionary[0][0] == 'remote':
        AV = 'A'
    elif cvss_info_dictionary[0][0] == 'local':
        AV = 'L'
    elif cvss_info_dictionary[0][0] == 'network':
        AV = 'N'

    # Access Complexity
    if cvss_info_dictionary[0][1] == 'low':
        AC = 'L'
    elif cvss_info_dictionary[0][1] == 'medium':
        AC = 'M'
    elif cvss_info_dictionary[0][1] == 'high':
        AC = 'H'

    # Authentication
    if cvss_info_dictionary[0][2] == 'not_required':
        Au = 'N'
    elif cvss_info_dictionary[0][2] == 'required':
        Au = 'S'
    elif cvss_info_dictionary[0][2] == 'multiple':
        Au = 'M'

    # Confidentiality
    if cvss_info_dictionary[0][3] == 'none':
        C = 'N'
    elif cvss_info_dictionary[0][3] == 'complete':
        C = 'C'
    elif cvss_info_dictionary[0][3] == 'partial':
        C = 'P'

    # Integrity
    if cvss_info_dictionary[0][4] == 'none':
        I = 'N'
    elif cvss_info_dictionary[0][4] == 'complete':
        I = 'C'
    elif cvss_info_dictionary[0][4] == 'partial':
        I = 'P'

    # Availability
    if cvss_info_dictionary[0][5] == 'none':
        A = 'N'
    elif cvss_info_dictionary[0][5] == 'complete':
        A = 'C'
    elif cvss_info_dictionary[0][5] == 'partial':
        A = 'P'

    # Exploitability
    if cvss_info_dictionary[0][6] == 'not_defined':
        E = 'ND'
    elif cvss_info_dictionary[0][6] == 'unproven':
        E = 'U'
    elif cvss_info_dictionary[0][6] == 'proof_of_concept':
        E = 'POC'
    elif cvss_info_dictionary[0][6] == 'functional':
        E = 'F'
    elif cvss_info_dictionary[0][6] == 'high':
        E = 'H'

    # Remediation Level
    if cvss_info_dictionary[0][7] == 'not_defined':
        RL = 'ND'
    elif cvss_info_dictionary[0][7] == 'official':
        RL = 'OF'
    elif cvss_info_dictionary[0][7] == 'workaround':
        RL = 'W'
    elif cvss_info_dictionary[0][7] == 'unavailable':
        RL = 'U'
    elif cvss_info_dictionary[0][7] == 'temporary':
        RL = 'TF'

    # Report Confidence
    if cvss_info_dictionary[0][8] == 'not_defined':
        RC = 'ND'
    elif cvss_info_dictionary[0][8] == 'confirmed':
        RC = 'C'
    elif cvss_info_dictionary[0][8] == 'unconfirmed':
        RC = 'UC'
    elif cvss_info_dictionary[0][8] == 'uncorroborated':
        RC = 'UR'

    vector = 'AV:%s/AC:%s/Au:%s/C:%s/I:%s/A:%s/E:%s/RL:%s/RC:%s' % (AV, AC, Au, C, I, A, E, RL, RC)

    cvss = CVSS2(vector)

    return cvss
