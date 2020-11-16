#!/usr/bin/env python3

#====================================================================================================
#                                      sslurry.py - Version 0.1
#                    A Python3 script to parse .nessus files for SSL related issues
#                            https://github.com/attackdebris/sslslurry
#====================================================================================================
# 
# Credit to Scapecom (onevault.tech) I leveraged his original code for my starting point 
#

import os
import sys
from sys import argv
import xml.etree.ElementTree as ET
import re
#import itertools as IT
import datetime

try:
	parse_file = sys.argv[1]
except IndexError:
	print('sslurry.py ( https://github.com/attackdebris/sslurry )\n')	
	print('Usage:')
	print('  ' + argv[0] + ' [nessus_file.nessus]')
	#print ('Output file created in "output" folder\n')
	sys.exit(2)

tree = ET.parse(parse_file)

data = []
new_host = ""
nessus_file = None
now = datetime.datetime.now()

#os.makedirs(os.path.dirname('output/'), exist_ok=True)

for host in tree.findall('Report/ReportHost'):
	ipaddr = host.find("HostProperties/tag/[@name='host-ip']").text

	for item in host.findall('ReportItem'):
		plugin_id       = item.get('pluginID')
		risk            = item.find('risk_factor').text
		#summary         = item.find('synopsis').text
		#details         = item.find('description').text
		#remediation     = item.find('solution').text
		name            = item.get('pluginName')
		port            = item.get('port')
		port_protocol   = item.get('protocol')
		#output          = item.find('plugin_output').text

		if (risk != 'None'):
			if nessus_file is not None:
				nessus_file.close()
			out_file = open('.ttmp.txt', 'a')
			out_file.write('PluginID ID: ' + plugin_id + ' - ' + name + '\n' + ipaddr + ':' + port + '/' + port_protocol + '\n')
			#out_file.write(str(output))
			#print('PluginID: ' + plugin_id + ' - ' + name + '\n' + ipaddr + ':' + port + '/' + port_protocol + '\n')

			new_host = ipaddr
    
print("==============================================================================================================\n")
print("                                      sslurry.py - Version 0.1")
print("                    A Python3 script to parse .nessus files for SSL related sslurry/issues")
print("                            https://github.com/attackdebris/sslslurry") 
print("\n")
print('      The following SSL data was parsed from Nessus file: "' + parse_file + '" on: ' + str(now.strftime('%Y-%m-%d %H:%M')))
print("\n==============================================================================================================")
print("\n======================================== SSL Protocol/Cipher Issues ========================================\n")

with open(".ttmp.txt") as origin_file:
        print("\n============================================================================")
        print("PluginID : 73412 - OpenSSL Heartbeat Information Disclosure (Heartbleed)")
        print("============================================================================\n")
        for line in origin_file:
                if re.search(r'73412', line):
                        for i in range(1):
                                print(next(origin_file), end='')

with open(".ttmp.txt") as origin_file:
        print("\n================================================================================================")
        print("PluginID : 78479 - SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)")
        print("================================================================================================\n")
        for line in origin_file:
                if re.search(r'78479', line):
                        for i in range(1):
                                print(next(origin_file), end='')

with open(".ttmp.txt") as origin_file:
        print("\n============================================================================")
        print("PluginID : 20007 - SSL Version 2 and 3 Protocol Detection")
        print("============================================================================\n")
        for line in origin_file:
                if re.search(r'20007', line):
                        for i in range(1):
                                print(next(origin_file), end='')

with open(".ttmp.txt") as origin_file:
	print("\n============================================================================")	
	print("PluginID : 42873 - SSL Medium Strength Cipher Suites Supported (SWEET32)")	
	print("============================================================================\n")
	for line in origin_file:
		if re.search(r'42873', line):
			for i in range(1):
				print(next(origin_file), end='')

with open(".ttmp.txt") as origin_file:
	print("\n============================================================================")
	print("PluginID : 65821 - SSL RC4 Cipher Suites Supported (Bar Mitzvah)")
	print("============================================================================\n")
	for line in origin_file:
		if re.search(r'65821', line):
			for i in range(1):
				print(next(origin_file), end='')

with open(".ttmp.txt") as origin_file:
        print("\n============================================================================")
        print("PluginID : 83875 - SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam)")
        print("============================================================================\n")
        for line in origin_file:
                if re.search(r'83875', line):
                        for i in range(1):
                                print(next(origin_file), end='')

with open(".ttmp.txt") as origin_file:
        print("\n============================================================================")
        print("PluginID : 104743 - Deprecated TLS Version 1.0 Protocol Use")
        print("============================================================================\n")
        for line in origin_file:
                if re.search(r'104743', line):
                        for i in range(1):
                                print(next(origin_file), end='')
print("\n======================================== SSL Certificate Issues ======================================\n")

with open(".ttmp.txt") as origin_file:
        print("\n============================================================================")
        print("PluginID : 51192 - SSL Certificates Cannot Be Trusted")
        print("============================================================================\n")
        for line in origin_file:
                if re.search(r'51192', line):
                        for i in range(1):
                                print(next(origin_file), end='')

with open(".ttmp.txt") as origin_file:
        print("\n============================================================================")
        print("PluginID : 35291 - SSL Certificates Signed Using Weak Hashing Algorithm")
        print("============================================================================\n")
        for line in origin_file:
                if re.search(r'35291', line):
                        for i in range(1):
                                print(next(origin_file), end='')

with open(".ttmp.txt") as origin_file:
        print("\n============================================================================")
        print("PluginID : 15901 - Expired SSL Certificates")
        print("============================================================================\n")
        for line in origin_file:
                if re.search(r'15901', line):
                        for i in range(1):
                                print(next(origin_file), end='')

with open(".ttmp.txt") as origin_file:
	print("\n===============================================================================")
	print("PluginID : 69551 - SSL Certificate Chain Contains RSA Keys Less Than 2048 bits")
	print("===============================================================================\n")
	for line in origin_file:
		if re.search(r'69551', line):
			for i in range(1):
				print(next(origin_file), end='')
	print('\n')
	os.remove(".ttmp.txt")
#print ('\nOutput saved to output/results.txt.\n')
