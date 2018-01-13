import socket
import sys
from threading import Thread

def recever(client_socket):
    while True:
        try:
            new_data = client_socket.recv(1024)
            if new_data:
                print(f'{new_data}')
            else:
                print('The server has closed this client.')
                break
        except Exception:
            print('The server has closed this client.')
            break

def writer(client_socket):
    while True:
        data = input()
        if data:
            if data == 'exit':
                break
            else:
                client_socket.sendall(str.encode(data))




client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('192.168.0.110', 56789)

client_socket.connect(server_address)

t = Thread(target=recever, args=(client_socket,))
t.daemon = True
t.start()

writer(client_socket)

print('The client is closed.')
client_socket.close()