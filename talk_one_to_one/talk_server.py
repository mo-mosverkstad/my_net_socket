import socket
import sys

MAX_CLIENT_NUMBER = 1
MAX_BUFFER_SIZE = 1024

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('192.168.0.110', 56789)
server_socket.bind(server_address)

server_socket.listen(MAX_CLIENT_NUMBER)

print(f'The server is waiting for client to connect, the server address is {server_address}')
client_socket, client_address = server_socket.accept()
print(f'The client has been connected, the client address is {client_address}')

while True:
    data = client_socket.recv(MAX_BUFFER_SIZE)
    if data: print(f'{data} <- clinet')
    else: break
    new_data = input('server ->')
    if new_data:
        if new_data == 'exit': break
        else: client_socket.sendall(str.encode(new_data))

print('The client socket is closed by server.')
client_socket.close()

print('The server socket is closed.')
server_socket.close()