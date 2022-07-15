# first of all import the socket library
import socket
import sys

# reserve a port on your computer in our
# case it is 1337 but it can be anything
# Define socket host and port
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 1337
MAX_BUFFER = 1024

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

    receive = client_socket.recv(MAX_BUFFER)
    print(f'[Server] server <- client: {receive.decode("utf-8")}')

    # send a thank you message to the client. encoding to send byte type.
    send = 'Thanks message from server'
    client_socket.send(send.encode())
    print(f'[Server] server -> client: {send}')

    # Close the connection with the client
    client_socket.close()
    print(f'[Server] close client connection {client_address} from server side')

    # Breaking once connection closed
    if 'bye' in receive.decode("utf-8"):
        break
    # break

# Close socket
server_socket.close()
print('[Server] Socket successfully closed')