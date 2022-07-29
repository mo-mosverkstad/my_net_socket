import socket
import sys
from ConversationProtocol import *

SERVER_PORT = 1337
SERVER_HOST = '127.0.0.1'
MAX_BUFFER = 1024
HOST_NAME = 'Sanndy'

parser = ConversationProtocolParser(VERSION_V1)

def send(socket, request):
    try:
        socket.send(request)
        print(f'[Client] server <- client: {request}')
    except socket.error:
        print('[Client] Send failed')
        sys.exit()

def recv(socket):
    response = socket.recv(MAX_BUFFER)
    print(f'[Client] server -> client: {response}')
    if response:
        print(f'[Conversation] {parser.decode(response)}')
        return parser.decode(response)
    else:
        return None, None



# create socket
try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
    print('[Client] Failed to create socket')
    sys.exit()
print('[Client] Socket successfully created')


# Connect to remote server
client_socket.connect((SERVER_HOST , SERVER_PORT))
print(f'[Client] Connecting to server {SERVER_HOST}:{SERVER_PORT}')

# Send CALL to server:
# 1st OCT: 0001 0001 => version: v1 (4 bits) command: call (4 bits)
# 2nd OCT: 0000 0001 => parameter: client_name (8 bits)
# 3rd OCT: xxxx xxxx => length of parameter client_name (8 bits)
# 4th OCT - Nth OCT  => value of paramter client_name, encode as ASCII (N x 8 bits)
send(client_socket, parser.encode(CMD_CALL_ID, [HOST_NAME]))

# Receive answer from server
cmd, _ = recv(client_socket)
if cmd == CMD_ANSW_NAME:
    while True:
        request = input('>')
        if request == 'bye':
            send(client_socket, parser.encode(CMD_RELS_ID, []))
        else:
            send(client_socket, parser.encode(CMD_REQU_ID, [request]))
        cmd, prm = recv(client_socket)
        if cmd == None or cmd == CMD_RELD_NAME: break
else:
    print('Server reject the call')


client_socket.close()
print('[Client] Socket successfully closed')

