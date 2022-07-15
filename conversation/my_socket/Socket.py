import socket

class Socket():
    def __init__(self, server_host = None, server_port = None):
        self.SERVER_HOST = server_host
        self.SERVER_PORT = server_port
        self.MAX_BUFFER = 1024
        if server_host and server_port:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.SERVER_HOST, self.SERVER_PORT))

    def set(self, socket):
        self.socket = socket
        return self

    def send(self, message:str):
        self.socket.send(message.encode())

    def receive(self) -> str:
        return self.socket.recv(self.MAX_BUFFER).decode("utf-8")

    def close(self):
        self.socket.close()