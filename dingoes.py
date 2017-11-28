#!/usr/bin/env python
#
# DiNgoeS: Compare anti-malware and phishing filtering DNS services
# Author: https://twitter.com/gszathmari
#

import os
import time
import argparse
import signal
from pyfiglet import Figlet
from halo import Halo
from sys import exit
from dingoes.hphosts import HpHostsFeed
from dingoes.report import Report
from dingoes.confparser import ConfParse

import logging

def print_banner():
    """Print welcome banner

    """
    figlet = Figlet(font='slant')
    banner = figlet.renderText('DiNgoeS')
    print(banner)
    print("[+] 2017 CryptoAUSTRALIA - https://cryptoaustralia.org.au\n")

def get_args():
    """Get command line arguments

    """
    epoch_time = int(time.time())
    report_filename = 'results' + "_" + time.strftime("%Y-%m-%d_%H%M") + '_' + str(epoch_time) + ".csv"
    parser = argparse.ArgumentParser(
        description='Compare DNS server responses.',formatter_class=argparse.MetavarTypeHelpFormatter)
    parser.add_argument('-o', type=str, default=report_filename, help='Report file name')
    parser.add_argument('-c', type=str, help='hpHosts feed (Default: PSH)', choices=['PSH', 'EMD', 'EXP'], default='PSH')
    parser.add_argument('-n', type=int, help='Number of hishing sites to test (Default: 500)', default=500)
    args = parser.parse_args()
    return args

def main():
    print_banner()
    args = get_args()
    spinner = Halo(spinner='dots')
    try:
        spinner.start(text='Parsing configuration file')
        config = ConfParse()
        spinner.succeed()
    except Exception as e:
        spinner.fail()
        print("\n\nError parsing configuration file: {}\n".format(e))
        exit(1)
    try:
        spinner.start(text="Retrieving hpHosts feed: {}".format(args.c))
        hphosts_feed = HpHostsFeed(args.c)
        spinner.succeed()
    except Exception as e:
        spinner.fail()
        print("\n\nError retrieving hpHosts feed: {}\n".format(e))
        exit(1)
    try:
        output_file = open(args.o, 'w')
    except Exception as e:
        print("\n\nError opening output file {}: {}\n".format(args.o, e))
        exit(1)
    # Create object and load in the retrieved values from above
    report = Report(hphosts_feed, output_file, config)
    # Process results
    try:
        print("\nProcessing {} entries, this may take a while:\n".format(args.n))
        statistics = report.write_results(args.n)
        output_file.close()
        # Generate some basic statistics
        print("\n\nBLOCKED SITES (Total: {})".format(args.n))
        print("===========================")
        for resolver in sorted(statistics.keys()):
            blocked_num = statistics[resolver]
            blocked_rate = round(statistics[resolver] / args.n * 100, 1)
            print("{}: {} ({}%)".format(resolver, blocked_num, blocked_rate))
        print("\nDetailed report: {}\n".format(args.o))
        print("Great success.\n")
    except Exception as e:
        print("Error: {}".format(e))
        exit(1)

def signal_handler(signal, frame):
    print('\n\nYou pressed Ctrl+C!\n')
    os._exit(1)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    main()
