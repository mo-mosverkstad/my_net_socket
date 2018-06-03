import socket
import sys
from ask_weather_constant import *

weather = {'2018-06-03':'Clear          26 degreeds', 
           '2018-06-04':'Clear          22 degreeds',
           '2018-06-05':'Cloudy         14 degreeds',
           '2018-06-06':'Clear          17 degreeds'}

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = (SERVER_IP_ADDRESS, SERVER_PORT)
server_socket.bind(server_address)

server_socket.listen(1)

print(f'The server is waiting for client to connect, the server address is {server_address}')
client_socket, client_address = server_socket.accept()
print(f'The client has been connected, the client address is {client_address}')

while True:
    data = client_socket.recv(BUFFER_SIZE).decode()
    if data:
           client_socket.sendall(weather.get(data, 'No information!').encode())
    else:
       break

print('The client socket is closed by server.')
client_socket.close()

print('The server socket is closed.')
server_socket.close()