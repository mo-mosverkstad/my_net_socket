# first of all import the socket library
import socket
import sys
from ConversationProtocol import *

# reserve a port on your computer in our
# case it is 1337 but it can be anything
# Define socket host and port
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 1337
MAX_BUFFER = 1024

HOST_NAME = 'Timmy'

parser = ConversationProtocolParser(VERSION_V1)

def send(socket, request):
    try:
        socket.send(request)
        print(f'[Server] server -> client: {request}')
    except socket.error:
        print('[Server] Send failed')
        sys.exit()

def recv(socket):
    response = socket.recv(MAX_BUFFER)
    print(f'[Server] server <- client: {response}')
    if response:
        print(f'[Conversation] {parser.decode(response)}')
        return parser.decode(response)
    else:
        return None, None

def socket_server_run():
    # create socket
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print('[Server] Failed to create socket')
        sys.exit()
    print('[Server] Socket successfully created')

    # Next bind to the port
    # we have not typed any ip in the ip field
    # instead we have inputted an empty string
    # this makes the server listen to requests
    # coming from other computers on the network
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    print(f'[Server] socket binded to {SERVER_HOST}:{SERVER_PORT}')

    # put the socket into listening mode
    server_socket.listen(5)
    print ("[Server] socket is listening")

    # a forever loop until we interrupt it or
    # an error occurs
    while True:

        # Establish connection with client.
        client_socket, client_address = server_socket.accept()
        print(f'[Server] Got connection from {client_address}')

        recv(client_socket)
        answer = input('ANSW / REJT ? >')
        if answer == CMD_ANSW_NAME:
            send(client_socket, parser.encode(CMD_ANSW_ID, [HOST_NAME]))
        else:
            send(client_socket, parser.encode(CMD_REJT_ID, ['User denied']))

        while True:
            cmd, prms = recv(client_socket)
            if cmd == None:
                break
            elif cmd == CMD_RELS_NAME:
                send(client_socket, parser.encode(CMD_RELD_ID, []))
                break
            elif cmd == CMD_REQU_NAME:
                response = input('>')
                send(client_socket, parser.encode(CMD_RESP_ID, [response]))
            else:
                # wrong cmd id
                send(client_socket, parser.encode(CMD_ERRR_ID, ['Wrong command ID']))

        # Close the connection with the client
        client_socket.close()
        print(f'[Server] close client connection {client_address} from server side')

        # Breaking once connection closed
        # break

try:
    socket_server_run()
except KeyboardInterrupt:
    # Close socket
    server_socket.close()
    print('[Server] Socket successfully closed')
    sys.exit()
