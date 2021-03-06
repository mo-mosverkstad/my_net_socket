import socket
import sys
from base_constant import *

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = (SERVER_IP_ADDRESS, SERVER_PORT)

client_socket.connect(server_address)
while True:
    data = input('client:>')
    if data == 'exit': break
    else: client_socket.sendall(str.encode(data))
    response_data = client_socket.recv(BUFFER_SIZE)
    if response_data:
        print(response_data.decode('utf-8'))
    else:
        break

print('The client is closed.')
client_socket.close()