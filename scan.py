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

	var b = require('bonescript');
var file = '/home/debian/out.txt';
let output = '';
b.readTextFile('/home/debian/out.txt', function (x){
    output = x.data;
    console.log('inside method output of x'+output);
});
setTimeout(function(){ 
     console.log("output of x:  "+output);
    b.writeTextFile(file, output+'heartbeat\n', readStatus);
}, 3000); 

function readStatus(x) {
    // console.log(JSON.stringify(x));
    // b.readTextFile(file, printStatus);
}
function printStatus(x) {
    // console.log(JSON.stringify(x));
}