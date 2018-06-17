import socket
import sys
from base_constant import *
from threading import Thread
from queue import Queue


def register(server_socket, message_queue):
    print(f'The server is waiting for client to connect, the server address is {server_address}')
    while True:
        client_socket, client_address = server_socket.accept()
        message_queue.put((MESSAGE_ID_REGIST, (client_address, client_socket)))
        print(f'The client has been connected, the client address is {client_address}')

def listener(client_socket, message_queue):
    while True:
        data = client_socket.recv(BUFFER_SIZE)
        message_queue.put((MESSAGE_ID_DATA_RECEVE, data))


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = (SERVER_IP_ADDRESS, SERVER_PORT)
server_socket.bind(server_address)

server_socket.listen(MAX_CLIENT_NUMBER)

message_queue = Queue()
Thread(target=register, args=(server_socket, message_queue)).start()

client_socket_list = list()

try:
    while True:
        if not message_queue.empty():
            msg = message_queue.get()
            msg_id, msg_body = msg
            if msg_id == MESSAGE_ID_REGIST:
                _, client_socket = msg_body
                client_socket_list.append(client_socket)
                Thread(target=listener, args=(client_socket, message_queue)).start()
            elif msg_id == MESSAGE_ID_DATA_RECEVE:
                for c in client_socket_list:
                    c.sendall(msg_body)

except KeyboardInterrupt:
    print('The client socket is closed by server.')
    for socket in client_socket_list:
        socket.close()
        print('The server socket is closed.')
        server_socket.close()


















while True:
    data = client_socket.recv()
    if data: client_socket.sendall(data)
    else: break

    data = client_socket2.recv(BUFFER_SIZE)
    if data: client_socket2.sendall(data)
    else: break

