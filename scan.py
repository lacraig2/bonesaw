import nmap
import argparse
from sys import version_info

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("ip")
	args = parser.parse_args()
	print("You have decided to scan "+args.ip)
	nm = nmap.PortScanner('/usr/bin/nmap')
	scan = nm.scan(args.ip,'22-443,3000,9090')
	command = scan['nmap']
	stats = scan['scanstats']
	results = scan['scan'][args.ip]
	relevant_results = results['tcp']
	if 22 in relevant_results:
		print("ssh is open")



if __name__ == "__main__":
	if version_info > (3,0):
		main()
	else:
		print("We only support Python 3.")

	