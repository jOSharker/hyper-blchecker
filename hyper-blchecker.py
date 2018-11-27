#!/usr/bin/env python
"""
blchecker.py: checks a list of DNS blocklists for hosts and IPs.
Given any hostname or IP address, this will try to resolve the matching
IP/hostname, and check for both in all blocklists. For every match that
is found, a warning is written to STDERR, and the return code will be 1.
Gevent is used for concurrent lookups, the number of active greenlets
is limited to PARALLELISM.

Inspired by https://github.com/DjinnS/check-rbl
Hosted at https://github.com/andreasf/check-dnsbl

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import sys
import socket
import ipaddress
import time
import ConfigParser
from multiprocessing import Pool

LOOKUP_TIMEOUT = 6
PARALLELISM = 10

config = ConfigParser.ConfigParser()
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
      #  sys.stderr.write("WARNING: %s found in spam blocklist %s!\n" % (host[-1], rbl))
        #f.write(time.strftime("%Y%m%d %H:%M:%S")+','+host[-1]+','+rbl+'\n')
       # sys.stderr.flush()
        return "WARNING: %s found in spam blocklist %s!\n" % (host[-1], rbl)
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
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)
    socket.setdefaulttimeout(LOOKUP_TIMEOUT)
    hosts_rbls = []
    #f = open('BL_'+time.strftime("%Y%m%d_%H%M%S")+'.csv','w')
    #f.write('DATE,IP/Host,BLACKLIST\n')
    #hostname_or_ip = "93.39.93.66/32"
  #  if hostname_or_ip : #
    for hostname_or_ip in sys.argv[1:]:     #('93.39.93.66'):
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
    print "START TIME: " + time.strftime("%Y%m%d_%H:%M:%S")
    in_rbl = exec_lookup_parallel(hosts_rbls)
    print in_rbl
    for element in in_rbl:
        f.write(element)
    print "END TIME: " + time.strftime("%Y%m%d_%H:%M:%S")
   # if in_rbl:
   #     sys.exit(1)


if __name__ in "__main__":
    f = open('BL_' + time.strftime("%Y%m%d_%H%M%S") + '.csv', 'w')
    main()
    f.close()