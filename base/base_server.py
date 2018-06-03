import socket
import sys
from base_constant import *

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = (SERVER_IP_ADDRESS, SERVER_PORT)
server_socket.bind(server_address)

server_socket.listen(1)

print(f'The server is waiting for client to connect, the server address is {server_address}')
client_socket, client_address = server_socket.accept()
print(f'The client has been connected, the client address is {client_address}')

while True:
    data = client_socket.recv(BUFFER_SIZE)
    if data: client_socket.sendall(data)
    else: break

print('The client socket is closed by server.')
client_socket.close()

print('The server socket is closed.')
server_socket.close()