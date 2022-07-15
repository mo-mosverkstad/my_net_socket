import socket
import sys  

SERVER_PORT = 1337
SERVER_HOST = '127.0.0.1'
MAX_BUFFER = 1024

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

# Send data to remote server
request = "bye message from client"

try:
    client_socket.send(request.encode())
    print(f'[Client] server <- client: {request}')
except socket.error:
    print('[Client] Send failed')
    sys.exit()

# Receive data
reply = client_socket.recv(MAX_BUFFER)
print(f'[Client] server -> client: {reply.decode("utf-8")}')

client_socket.close()
print('[Client] Socket successfully closed')

