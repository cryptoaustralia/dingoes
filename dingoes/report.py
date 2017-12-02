import csv
import re
from etaprogress.progress import ProgressBar
from dateutil.parser import parse
from netaddr import *
from dingoes.resolver import DnsResolver
from ascii_graph import Pyasciigraph
from ascii_graph.colors import *
from ascii_graph.colordata import vcolor

class Report(object):
    '''Report class'''
    def __init__(self, hphosts_feed, output_file, config):
        self.hphosts_feed = hphosts_feed
        self.output_file = output_file
        self.output_file_handler = False
        self.config = config
        self.resolver = DnsResolver()
        self.csv_writer = False
        self.resolvers = config.confvalues
        self.resolver_names = config.confvalues.keys()
        self.statistics = {}

    def is_blocked(self, ip_addresses, blockpages):
        '''Verifies whether the IP address is on the blocked page list'''
        # TODO: blockpages should be generated from self.config
        intersection = ip_addresses & blockpages
        # If response was NXDOMAIN, we need to verify if non-filtering servers respond
        if IPAddress('255.255.255.255') in ip_addresses:
            try:
                ip_addresses = self.resolver.get_ip_address(domain)
            # If response is NXDOMAIN or any other error, return False
            except:
                return False
            # If Google responds with a valid DNS response, blocking is successful
            else:
                # Return NXDOMAIN instead of 255.255.255.255 representing it
                response = 'NXDOMAIN'
                return response
        elif len(intersection) > 0:
            # If the IP address is in the list of IP addresses of block pages
            # the website is blocked successfully
            return intersection
        # Return 'non-blocked' in case of any other errors
        else:
            return False

    def generate_result(self, ip_addresses, blockpages, resolver_name):
        """
        Generates cell content in the CSV file
        """
        result = False
        # Return 'SITE_BLOCKED_OK' if the phishing site's domain name resolves to
        # one of the block pages of the DNS services.
        if self.is_blocked(ip_addresses, blockpages):
            result = 'SITE_BLOCKED_OK'
            self.add_to_stats(resolver_name)
        # If the website is not blocked, return with the website's IP address
        else:
            results = []
            for ip_address in ip_addresses:
                results.append(str(ip_address))
            result = "\n".join(results)
        return result

    def open_csv_file(self):
        '''Open CSV file and add header'''
        try:
            self.output_file_handler = open(self.output_file, 'w')
        except Exception as e:
            print("\n\nError opening output file {}: {}\n".format(args.o, e))
            exit(1)
        csv_header_fieldnames = [
            'Added to hpHosts',
            'Phishing Site Domain',
            'Phishing Site IP Address'
        ]
        csv_header_fieldnames.extend(self.resolver_names)
        csv_writer = csv.DictWriter(self.output_file_handler, delimiter=',', fieldnames=csv_header_fieldnames)
        csv_writer.writeheader()
        return csv_writer

    def write_results(self, entries_to_process):
        '''Write results into CSV file'''
        counter = 1
        # Create progress bar
        bar = ProgressBar(entries_to_process, max_width=72)
        # Write CSV header
        csv_writer = self.open_csv_file()
        # Iter through each feed entry from the hpHosts feed
        for feed_entry in self.hphosts_feed.entries:
            # Stop processing if the number of entries are higher than in '-n'
            if counter > entries_to_process:
                break
            result = {}
            # Update progress bar
            bar.numerator = counter
            print(bar, end='\r')
            # Write phishing site details into CSV
            result['Phishing Site Domain'] = feed_entry.title
            result['Added to hpHosts'] = parse(feed_entry.published)
            result['Phishing Site IP Address'] = re.findall(r'[0-9]+(?:\.[0-9]+){3}', feed_entry.summary)[0]
            # Iterate through the third-party DNS services
            for resolver_name in self.resolver_names:
                try:
                    dns_resolvers = self.resolvers[resolver_name]['resolvers']
                    phishing_domain = result['Phishing Site Domain']
                    resolver = DnsResolver(dns_resolvers)
                    # Retrieve the IP addresses that the third-party DNS service resolves
                    ip_addresses = resolver.get_ip_address(phishing_domain)
                except Exception as e:
                    # Write DNS lookup error message in the CSV file
                    result[resolver_name] = e
                else:
                    blockpages = self.resolvers[resolver_name]['blockpages']
                    result[resolver_name] = self.generate_result(ip_addresses, blockpages, resolver_name)
            # Write results into file
            csv_writer.writerow(result)
            # Flush file after writing each line
            self.output_file_handler.flush()
            counter += 1
        # Close output file
        self.output_file_handler.close()
        return counter

    def add_to_stats(self, resolver_name):
        # If statistics variable is not initialised:
        if len(self.statistics.keys()) > 0:
            self.statistics[resolver_name] += 1
        else:
            for item in self.resolver_names:
                self.statistics[item] = 0

    def print_stats_diagram(self, total_entries):
        data = []
        graph = Pyasciigraph(separator_length=4)
        for resolver_name in sorted(self.resolver_names):
            item = (resolver_name, self.statistics[resolver_name])
            data.append(item)
        item = ('TOTAL', total_entries)
        data.append(item)
        for line in graph.graph('Blocking Statistics:', data):
            print(line)
