#!/usr/bin/env python
import nmap
import argparse
from sys import version_info, path
from pwn import *
from time import sleep

def check_ssh(ip,user,passwd):
	try:
		s =  ssh(host=ip,
	       user=user,
	       password=passwd,port=22)
		return s.download_data("/home/luke/.bash_history") is not None
	except:
		return False

def main():
	# parse arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("ip")
	parser.add_argument("-aggr","-aggressive", '--aggressive', action="store_true")
	args = parser.parse_args()

	# notify user that the scan is beginning
	print("Scanning "+args.ip+"...")
	nm = nmap.PortScanner()
	scan = nm.scan(args.ip,'21-443,3000,8080,9090')
	
	# parse results
	command = scan['nmap']
	stats = command['scanstats']
	scan_scan = scan['scan']
	results = scan_scan[scan_scan.keys()[0]] # this is the ip address
	relevant_results = results['tcp'] 		 # these indicate open ports

	# Checking SSH
	if 22 in relevant_results:
		print("Port 22: SSH is open") # notify user
		# in the event that we are agressive we try some basic passwords
		if args.aggressive:
			pwd_map = [("root",""),("root","temppwd"),("debian",""),("debian","temppwd")]
			for i in pwd_map:
				works = check_ssh(args.ip,i[0],i[1])
				print("attempt: "+str(i)+" "+works)
	# Checking HTTP Port 80
	if 80 in relevant_results:
		print("Port 80: http is open")

		#lets check to see if its Bone101
		result = wget("http://"+args.ip, timeout=20)
		if "Bone101" in result:
			print("Server running open Bone101.")
			if args.aggressive:
				pass
		else:
			print("Server not running Bone101.")

			
	if 3000 in relevant_results:
		print("Port 3000 open")
		result = wget("http://"+args.ip+":3000",timeout=20)
		if "Cloud9" in result:
			print("Server running Cloud9.")
			if args.aggressive:
				pass
		else:
			print("Server not running Cloud9.")
		#42["bonescript$readTextFile",{"filename":"/home/debian/out.txt","seq":12}]
		#42["bonescript$writeTextFile",{"filename":"/home/debian/out.txt","data":"heartbeat\nheartbeat\nheartbeat\nheartbeat\nheartbeat\nheartbeat\nheartbeat\nheartbeat\nheartbeat\nheartbeat\nheartbeat\ndatatoappend\n","seq":13}]
	if 8080 in relevant_results:
		print("apache httpd running on port 8080")

if __name__ == "__main__":
	main()
