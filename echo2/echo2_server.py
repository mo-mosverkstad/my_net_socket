import socket
import sys
import queue
from threading import Thread

MAX_CLIENT_NUMBER = 2
MAX_RECEIVE_BUFFER_SIZE = 1024

def on_client_echo(clinet_socket):
    while True:
        data = clinet_socket.recv(MAX_RECEIVE_BUFFER_SIZE)
        if data: clinet_socket.sendall(data)
        else: break
    print('the client is closed!')
    client_socket.close()

def on_client_connect(server_socket, client_socket_queue):
    while True:
        client_socket, client_address = server_socket.accept()
        print(f'The server receives the connection from {client_address}')
        client_socket_queue.put((client_socket, client_address))

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('192.168.0.110', 56789)
server_socket.bind(server_address)
server_socket.listen(MAX_CLIENT_NUMBER)
print(f'The server is waiting for client to connect, the server address is {server_address}')


client_socket_queue = queue.Queue()
client_connect_thread = Thread(target=on_client_connect, args=(server_socket, client_socket_queue))
client_connect_thread.daemon = True
client_connect_thread.start()

clients_dict = dict()
clients_id = 0

while True:
    if not client_socket_queue.empty():
        client_socket, client_address = client_socket_queue.get()
        client_thread = Thread(target=on_client_echo,args=(client_socket,))
        client_thread.daemon = True
        client_thread.start()
        clients_dict[clients_id] = (client_socket, client_address, client_thread)
        clients_id += 1
        print(clients_dict)

