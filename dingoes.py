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
    report_filename = "report_{}_{}.csv".format(time.strftime("%Y-%m-%d_%H%M"), epoch_time)
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
    # Create object and load in the retrieved values from above
    report_filename = "hpHosts-{}-{}".format(args.c, args.o)
    report = Report(hphosts_feed, report_filename, config)
    # Process results
    print("\nProcessing {} entries, this may take a while:\n".format(args.n))
    report.write_results(args.n)
    print("\nGreat success.\n")
    stats = report.print_stats(args.n)
    print(stats)
    print("Detailed report is available in {}\n".format(report_filename))

def signal_handler(signal, frame):
    print('\n\nYou pressed Ctrl+C!\n')
    os._exit(1)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    main()
