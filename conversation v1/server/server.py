import sys
sys.path.append('..')
from my_socket import *

class Server(SocketWrapper):
    def run(self):
        while self.running:
            client_connection, client_address = self.socket_object.accept()
            receive = client_connection.recv(self.MAX_BUFFER)
            print("Received message", receive)
            user_input = input()
            if user_input == "bye":
                self.running = False
            client_connection.send(user_input.encode())
            client_connection.close()
        self.close()

Server().run()