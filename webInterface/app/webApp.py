#!/usr/bin/env python3

from flask import Flask, render_template, session, request
from flask_socketio import SocketIO, emit, disconnect
import shodan
import nmap
import argparse
from sys import version_info, path
import requests
from time import sleep

SHODAN_API_KEY = "LImwdILg9P8WtWvfwYMn3X5iyBpKAaRO"

shodanAPI = shodan.Shodan(SHODAN_API_KEY)

async_mode = None

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ECE497-01'
socketio = SocketIO(app, async_mode=async_mode)
thread = None

UPDATE_LIST = "u"

buttons = [UPDATE_LIST]

@app.route('/')
def SearchPage():
    return render_template('page.html', async_mode = socketio.async_mode)

@socketio.on('my_event')
def test_message(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
         {'data': message['data'], 'count': session['receive_count']})
         
@socketio.on('more_data')
def get_ip_data(requested_ip):
    session['receive_count'] = session.get('receive_count', 0) + 1
    host = shodanAPI.host(requested_ip['data'])
    emit('clear_more_data')
    emit('more_data',
         {'data': 'Organization: %s\n' % host.get('org', 'n/a')})
    emit('more_data',
         {'data': 'Operating System: %s\n' % host.get('os', 'n/a')})
    for item in host['data']:
        emit('more_data',
             {'data': 'Port: %s\n' % item['port']})
        emit('more_data',
             {'data': 'Banner: %s\n' % item['data']})
    emit('my_response',
         {'data':'More data requested for ip: %s' % requested_ip['data'], 'count': session['receive_count']})
             
@socketio.on('scan_ip')
def start_scan(target_ip):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
         {'data': 'IP scan requested for IP: %s' % target_ip['data'], 'count': session['receive_count']})
    emit('clear_scan_data')
    scan(target_ip['data'])
      

@socketio.on('my_broadcast_event')
def test_broadcast_message(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
         {'data': message['data'], 'count': session['receive_count']},
         broadcast=True)


@socketio.on('my_ping')
def ping_pong():
    emit('my_pong')
    
@socketio.on('button')
def button(num):
    session['receive_count'] = session.get('receive_count', 0) + 1
    if num == 0:
        try:
        # Search Shodan
            results = shodanAPI.search('beaglebone')
            emit('clear_iplist')

        # Show the results
            print( 'Results found: %s' % results['total'])
            for result in results['matches']:
                #print('IP: %s' % result['ip_str'])
                emit('my_iplist',
                     {'data': 'IP: %s' % result['ip_str']})
                # print(result['data'])
                #print('')
            emit('my_response',
                 {'data': 'Update success ', 'count': session['receive_count']})
        except shodan.APIError as e:
            print('Error: %s' % e)
            emit('my_response',
                 {'data': 'Update Error ', 'count': session['receive_count']})
    print("Button")
    print(num)
    # sys.exit()

@socketio.on('connect')
def test_connect():
    # global thread
    # if thread is None:
    #     thread = socketio.start_background_task(target=background_thread)
    emit('my_response', {'data': 'Connected', 'count': 0})


@socketio.on('disconnect')
def test_disconnect():
    print('Client disconnected', request.sid)
    
    
    
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
            print(relevant_results[53]["version"])
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


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', debug=False)
