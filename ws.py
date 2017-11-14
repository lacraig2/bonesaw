from socketIO_client import SocketIO, BaseNamespace

class Namespace(BaseNamespace):

    def on_connect(self):
        print('[Connected]')

def on_response(*args):
    print("response ",args)

socketIO = SocketIO('192.168.7.2', 80, Namespace)
socketIO.emit("EIO=3&transport=polling&t=L-NVo8e&sid=LQ8gwX5uWsl6DnwVAAAX",on_response)
socketIO.wait()
