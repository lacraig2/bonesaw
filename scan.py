#!/usr/bin/env python
import nmap
import argparse
from sys import version_info, path


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("ip")
	args = parser.parse_args()
	print("You have decided to scan "+args.ip)
	nm = nmap.PortScanner()
	scan = nm.scan(args.ip,'21-443,3000,8080,9090')
	# print(scan)
	command = scan['nmap']
	stats = command['scanstats']
	scan_scan = scan['scan']
	results = scan_scan[scan_scan.keys()[0]]
	print("IP address determined: "+ scan_scan.keys()[0])
	relevant_results = results['tcp']
	if 22 in relevant_results:
		print("ssh is open")
	if 3000



if __name__ == "__main__":
	main()
