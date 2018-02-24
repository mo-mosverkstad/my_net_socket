import socket
import sys

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('192.168.0.110', 56789)

client_socket.connect(server_address)
while True:
    data = input('client:>')
    if data == 'exit': break
    else: client_socket.sendall(str.encode(data))
    new_data = client_socket.recv(1024)
    if new_data:
        print (new_data)
    else:
        break

print('The client is closed.')
client_socket.close()
