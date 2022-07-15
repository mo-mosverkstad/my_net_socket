import socket
from .Socket import Socket

class ServerSocket():
    def __init__(self, port = 1337):
        self.HOST = '127.0.0.1'
        self.PORT = port
        self.MAX_BUFFER = 1024
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.HOST, self.PORT))
        self.socket.listen(5)

    def accept(self):
        client_socket, _ = self.socket.accept()
        return Socket().set(client_socket)

    def close(self):
        self.socket.close()