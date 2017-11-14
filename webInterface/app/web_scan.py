#!/usr/bin/env python
import nmap
import argparse
from sys import version_info, path
import requests
from time import sleep


# def check_ssh(ip,user,passwd):
# 	try:
# 		s =  ssh(host=ip,
# 	       user=user,
# 	       password=passwd,port=22)
# 		return s.download_data("/home/luke/.bash_history") is not None
# 	except:
# 		return False


def scan(ip):

	# notify user that the scan is beginning
	print("Scanning "+ip+"...")
	nm = nmap.PortScanner()
	scan = nm.scan(ip,'21-443,3000,8080,9090')
	isRed = 0
	isYellow = 0
	
	# parse results
	command = scan['nmap']
	stats = command['scanstats']
	scan_scan = scan['scan']
	if not scan_scan:
		print("Scan failed. No results returned. Check that host is up.")
		return
	results = scan_scan[list(scan_scan.keys())[0]] # this is the ip address
	relevant_results = results['tcp'] 		 # these indicate open ports

	# Checking SSH
	if 22 in relevant_results:
		print("Port 22: SSH is open") # notify user
		emit('scan_data',
			 {'data': 'Port 22: SSH is open'})

	# Checking HTTP Port 80
	if 80 in relevant_results:
		print("Port 80: http is open")
		emit('scan_data',
			 {'data': 'Port 80: http is open'})

		#lets check to see if its Bone101
		result = requests.get("http://"+ip, timeout=20)
		# print('text: ', result.text)
		if "Bone101" in result.text:
			print("Server running open Bone101.")
			emit('scan_data',
				 {'data': 'Warning: Server running open Bone101'})
			isRed = 1
			
		else:
			print("Server not running Bone101.")
			emit('scan_data',
				 {'data': 'Server not running Bone101'})
	if 53 in relevant_results:
		print("Port 53: DNSMASQ is open")
		emit('scan_data',
			 {'data': 'Port 53: DNSMASQ is open'})
		if "version" in relevant_results[53]:
			version = relevant_results[53]["version"].split(".")
			maj_version = int(version[0])
			min_version = int(version[1])
			if maj_version <=2 and min_version <= 78:
				print("[DNSMASQ] version is vulnerable")
				isYellow = 1
			else:
				print("[DNSMASQ] version is not vulnerable")
		else:
			print("[DNSMASQ] no version information returned.")
			
	if 3000 in relevant_results:
		print("Port 3000 open")
		emit('scan_data',
			 {'data': 'Port 3000: Open'})
		result = requests.get("http://"+ip+":3000",timeout=20)
		if "Cloud9" in result.text:
			print("Server running Cloud9.")
			isRed = 1
			
		else:
			print("Server not running Cloud9.")

	if 8080 in relevant_results:
		print("Port 8080: HTTPD running on port 8080")
		emit('scan_data',
			 {'data': 'Port 8080: HTTPD running on port 8080'})
		if "version" in relevant_results[8080]:
			version = relevant_results[8080]["version"].split(".")
			maj_version = int(version[0])
			mid_version = int(version[1])
			min_version = int(version[2])
			if maj_version <=2 and mid_version <= 4 and min_version <= 25:
				print("[HTTPD] version is vulnerable")
				isYellow = 1
			else:
				print("[HTTPD] version is not vulnerable")
		else:
			print("[HTTPD] no version information returned.")
			
	if isRed:
		emit('scan_color_update',
			 {'data': 'red'})
	elif isYellow:
		emit('scan_color_update',
			 {'data': 'yellow'})

def main():
	# parse arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("ip")
	parser.add_argument("-aggr","-aggressive", '--aggressive', action="store_true")
	parser.add_argument("-mean","-mean","--mean",action="store_true")
	args = parser.parse_args()

	if "*" in args.ip:
		ip = ".".join(args.ip.split(".")[:3])+"."
		for i in range(1,256):
			if "*" in ip:
				print("we are not scanning over anything bigger than a subnet")
				return
			scan(ip+str(i))

	else:
		scan(args.ip)


if __name__ == "__main__":
	main()
