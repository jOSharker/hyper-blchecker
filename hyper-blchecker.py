#!/usr/bin/env python
"""
hyper-blchecker.py: checks a list of DNS blocklists for hosts and IPs.
Given any hostname, IP address or subnet (CIDR format), this will try to resolve the matching
IP/hostname, and check for both in all blocklists enabled. For every match that
is found, a warning is written on screen and is possible to use the option: -o to save the results in a CSV file.
"""

import sys
import socket
import ipaddress
import time
import ConfigParser
from multiprocessing import Pool
import argparse

LOOKUP_TIMEOUT = 6
PARALLELISM = 10

config = ConfigParser.ConfigParser()
parser = argparse.ArgumentParser()



config.read("./hyper-blchecker.properties")

#####Importing the DNSBL lists
DNS_BLS = config.get('DNSBLs', 'DNS_BLS').split(',\n')
# DBL only lists hostnames. Spamhaus doesn't want you to query it for IPs, so they return a false positive for each IP address.
HOST_LOOKUP_ONLY = config.get('HOST_LOOKUP_ONLY', 'HOST_LOOKUP_ONLY').split(',\n')
# This is the list of BL which need an activation code or a password to return the right value
DNS_BL_PAY4 = config.get('PAY4_DNSBL','PAY4_DNSBL').split(',\n')
#Evaluation of the DNSBL sizing to create the thread pool to maximize the performance
POOL = PARALLELISM | len(DNS_BLS) + len(HOST_LOOKUP_ONLY)

for bl in DNS_BL_PAY4:
    section = 'PAY4_'+str(bl).strip('\n')
    if config.has_option(section,'ENABLED') and str(config.get(section,'ENABLED')).lower() == 'yes':
        if str(config.get(section, 'AUTH')).lower() == 'key':
            key = config.get(section, 'CODE')
            url = key + '.' + str(bl).strip('\n')
            DNS_BLS.append(url)
            # Evaluation of the DNSBL sizing to create the thread pool to maximize the performance
            POOL = POOL +1
##### Import completed



# Definition of a class to manage IPs and hostnames to be provided to the right BLs
class Host:
    def __init__(self, hostname=None, addr=None):
        self.hostname = hostname
        self.addr = addr

    def inverse_addr(self):
        """
        IPs are listed backwards, e.g. IP 1.2.3.4 -> 4.3.2.1.pbl.spamhaus.org
        """
        if self.addr is None:
            return None
        addr_split = self.addr.split(".")
        addr_split.reverse()
        return ".".join(addr_split)

# Function used to convert from CIDR format to a list of IPs
def cidr_to_ips(cidr_net):
    #conversion to unicode to use the ipaddress library
    unicodeversion = unicode(cidr_net)
    net = ipaddress.ip_network(unicodeversion,False)
    #net = ipaddress.ip_network('10.10.10.10/25')
    return net

def lookup(host_rbl):
    """
    Looks up a host in blacklist, returns whether it exists.
    Expects a tuple of (host, rbl), where host again is a tuple, of any
    length. The first field of host is used for the lookup (i.e. hostname
    or inverse ip), and the last field is printed in warning messages.
    """
    host, rbl = host_rbl
    rblhost = host[0] + "." + rbl
    try:
        socket.gethostbyname(rblhost)
        return host[-1]+","+ rbl
    except socket.gaierror:
        return False


def exec_lookup_parallel(hosts_rbls):
    p = Pool(POOL)  # Pool tells how many at a time

    in_rbl = []
    ret = p.map(lookup, hosts_rbls)
    for result in ret:
        if result != False:
            in_rbl.append(result)
    p.terminate()
    p.join()
    return in_rbl


def print_usage():
    sys.stderr.write("usage: %s <host.name or IP> [host2.name or IP] ...\n" % sys.argv[0])
    sys.stderr.flush()


def get_host_and_ip(host_or_ip):
        """
        Given a hostname or ip address, this returns a Host instance with
        hostname and ip. One of the Host fields may be None, if a lookup
        fails.
        """
        host = host_or_ip
        addr = None
        try:
            addr = socket.gethostbyname(host)
            if addr == host:
                # addr and host are the same ip address
                host = socket.gethostbyaddr(addr)[0]
        except socket.gaierror:
            # no addr for hostname
            return Host(hostname=host)
        except socket.herror:
            # no hostname for addr
            return Host(addr=addr)
        return Host(hostname=host, addr=addr)


def main():
  #  if len(sys.argv) < 2:
  #      print_usage()
  #      sys.exit(1)

    #parser.add_argument("-ver", help="increase output verbosity")

    parser.add_argument("IPs", nargs='+', help="List of hostnames, IPs and subnets to be checked")
    parser.add_argument("-o", "--output", help="Filename where to save the output")
    parser.add_argument("-csv", "--csv", help="Output in csv format", action='store_true')
    args = parser.parse_args()
    #if args.ver:
    #    print "verbosity turned on"
    #if args.IPs:
    #    print args.IPs
    socket.setdefaulttimeout(LOOKUP_TIMEOUT)
    hosts_rbls = []
    #hostname_or_ip = "93.39.93.66/32"
    #if hostname_or_ip : #
    #for hostname_or_ip in sys.argv[1:]:
    for hostname_or_ip in args.IPs:
        #check if CIDR format or not
        if hostname_or_ip.find('/') > 0:
            net = cidr_to_ips(hostname_or_ip)
        else:
            net = [hostname_or_ip]

        for newhostname_or_ip in net:
            #use of str function to convert from IPv4 to string
            host = get_host_and_ip(str(newhostname_or_ip))
            for rbl in DNS_BLS:
                #print rbl
                rbl = rbl.strip('\n')
                if host.hostname is not None:
                    hosts_rbls.append(((host.hostname,), rbl))
                if rbl not in HOST_LOOKUP_ONLY and host.addr is not None:
                    hosts_rbls.append(((host.inverse_addr(), host.addr), rbl))
   # print "####################################START"
   # print hosts_rbls
   # print "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$CLOSED"
    start_time = time.strftime("%Y%m%d_%H:%M:%S")
    in_rbl = exec_lookup_parallel(hosts_rbls)
    #print in_rbl
    if args.csv:
        if args.output:
            f = open(args.output, 'w')
        else:
            f = open('BL_' + time.strftime("%Y%m%d_%H%M%S") + '.csv', 'w')
        f.write("IP/HOSTNAME,BLACKLIST\n")
        for element in in_rbl:
            f.write(element + "\n")
        f.close()

    print "IP/HOSTNAME,BLACKLIST"
    for element in in_rbl:
        print str(element).strip("\n")
    print "START TIME: " + start_time + " END TIME: " + time.strftime("%Y%m%d_%H:%M:%S") + " # of actions to unblock: " + str(len(in_rbl))
   # if in_rbl:
   #     sys.exit(1)


if __name__ in "__main__":

    main()
