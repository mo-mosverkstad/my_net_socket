import socket

class SocketWrapper:
    def __init__(self):
        self.SERVER_HOST = '127.0.0.1'
        self.SERVER_PORT = 1337
        self.MAX_BUFFER = 1024
        self.running = True
        self.socket_object = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__init()

    def __init(self):
        self.socket_object.bind((self.SERVER_HOST, self.SERVER_PORT))
        self.socket_object.listen(5)
        print("Socket successfully created")

    def run(self):
        pass

    def close(self):
        self.socket_object.close()
        print("Socket successfully closed")