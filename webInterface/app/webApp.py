#!/usr/bin/env python3

from flask import Flask, render_template, session, request
from flask_socketio import SocketIO, emit, disconnect
import shodan

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
         {'data': 'Organization: %s' % host.get('org', 'n/a')})
    emit('more_data',
         {'data': 'Operating System: %s' % host.get('os', 'n/a')})
    for item in host['data']:
        emit('more_data',
             {'data': 'Port: %s' % item['port']})
        emit('more_data',
             {'data': 'Banner: %s' % item['data']})
    emit('my_response',
         {'data':'More data requested for ip: %s' % requested_ip['data'], 'count': session['receive_count']})
             
@socketio.on('scan_ip')
def start_scan(target_ip):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
         {'data': 'IP scan requested for IP: %s' % target_ip['data'], 'count': session['receive_count']})
      

@socketio.on('my_broadcast_event')
def test_broadcast_message(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
         {'data': message['data'], 'count': session['receive_count']},
         broadcast=True)

@socketio.on('disconnect_request')
def disconnect_request():
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
         {'data': 'Disconnected!', 'count': session['receive_count']})
    disconnect()


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

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', debug=False)
