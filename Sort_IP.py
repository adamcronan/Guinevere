# Takes in a tuple of IP addresses and hostnames and sorts them
# Python Imports
import netaddr

def ip_sort_tuple(hosts):
    """Put the provided list of tuples IP addresses into order"""

    ips = []
    hostnames = []
    for ip in hosts:
        if unicode(ip[0].split('.')[0]).isnumeric():
            ips.append(netaddr.IPAddress(ip[0]))  # isnumeric only works with Unicode; checking for IP
        else:
            hostnames.append(ip[0])

    ips = sorted(ips)
    sorted_hosts = []
    for i in ips:                   # Add IPs
        sorted_hosts.append(str(i))
    for i in hostnames:             # Add Hostnames
        sorted_hosts.append(str(i))
    return sorted_hosts

def ip_sort_list(hosts):
    """Put the provided list IP addresses into order"""
    # TODO normalize both ip_sort functions to only use one data type (list or tuple)
    ips = []
    hostnames = []
    for ip in hosts:
        if unicode(ip.split('.')[0]).isnumeric():
            ips.append(netaddr.IPAddress(ip))  # isnumeric only works with Unicode; checking for IP
        else:
            hostnames.append(ip)

    ips = sorted(ips)
    sorted_hosts = []
    for i in ips:                   # Add IPs
        sorted_hosts.append(str(i))
    for i in hostnames:             # Add Hostnames
        sorted_hosts.append(str(i))
    return sorted_hosts