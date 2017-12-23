# My imports
from Guinevere import get_Guinevere_variables

__version__ = get_Guinevere_variables('version')

def print_banner():
    """Guinevere's banner"""
    #Art retrieved from http://www.oocities.org/spunk1111/women.htm

    print """        ,,,_"""
    print """     .'     `'. ################################################"""
    print "    /     ____ \\#               Guinevere v"+__version__+"               #"
    print "   |    .`_  _\/#                                              #"
    print "   /    ) a  a| #   Automated Security Assessment Reporting    #"
    print "  /    (    > | ################################################"
    print """ (      ) ._  / """
    print " )    _/-.__.'`\\"
    print """(  .-'`-.   \__ )"""
    print """ `/      `-./  `.         """
    print "  |    \      \  \\"
    print "  |     \   \  \  \\"
    print "  |\     `. /  /   \\"
    print "_________________________________________________________________"