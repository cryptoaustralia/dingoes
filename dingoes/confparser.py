import re
import configparser
from validators.ip_address import ipv4
from validators.domain import domain
from netaddr import *
from dingoes.resolver import DnsResolver

class ConfParse(object):
    '''ConfParse class'''
    def __init__(self, file_name="services.ini"):
        self.file_name = file_name
        self.config_parser = False
        self.config = {}
        self.dns_resolver = DnsResolver()
        self.main()

    def main(self):
        self.config_parser = configparser.ConfigParser()
        self.config_parser.read_file(open(self.file_name))
        for entry in self.config_parser.sections():
            resolvers = self.config_parser[entry]['resolvers']
            blockpages = self.config_parser[entry]['blockpages']
            self.config[entry] = {
                'resolvers': self.parse_resolvers(resolvers),
                'blockpages': self.parse_blockpages(blockpages)
            }

    def parse_resolvers(self, resolvers):
        '''Parses IP addresses from the configuration file'''
        # TODO: Change this to IPSet()
        result = []
        # Strip whitespaces
        resolvers_list = [x.strip() for x in resolvers.split(',')]
        # Validate IP addresses
        for ip_address in resolvers_list:
            # If the IP is valid, add to the results
            if ipv4(ip_address):
                result.append(ip_address)
            else:
                raise Exception("Invalid IP address in configuration file: {}".format(ip_address))
        return result

    def parse_blockpages(self, blockpages):
        '''
        Parses 'blockpages =' entry from the configuration file

        Get the IP address or domain name from the config file of the blocked pages
        and add them into an IPSet.
        '''
        result = IPSet()
        # Split entries from the config file and strip whitespaces
        blockpages_list = [x.strip() for x in blockpages.split(',')]
        # Process the IP addresses and domains
        for blockpage in blockpages_list:
            # If the DNS server blocks the query with NXDOMAIN
            if blockpage == 'NXDOMAIN':
                # Represent NXDOMAIN with 255.255.255.255/32
                result.add('255.255.255.255/32')
            # If the block page is hosted on a simple IP address
            elif ipv4(blockpage):
                result.add(blockpage)
            # If the block page is hosted somewhere on a subnet
            elif re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|)', blockpage):
                result.add(blockpage)
            # If the block page is hosted under a CNAME record
            elif domain(blockpage):
                try:
                    result = self.dns_resolver.get_ip_address(blockpage)
                except Exception as e:
                    print("\nDNS resolution error while retrieving list of block pages: {}\n".format(e))
                    exit(1)
            # If the 'blockpage = ' has a 'none' value (e.g. Google DNS doesn't have a block page)
            elif blockpage == 'none':
                pass
            # Throw exception if an invalid entry is found
            else:
                raise Exception("Invalid entry found: {}".format(blockpage))
        return result

    @property
    def confvalues(self):
        return self.config
