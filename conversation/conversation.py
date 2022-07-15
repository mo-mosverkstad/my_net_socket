from my_socket import ServerSocket

server_socket = ServerSocket(1337)
socket = server_socket.accept()

while True:
    client_message = socket.receive()
    print(client_message)
    if client_message == "bye": break
    user_input = input(">")
    socket.send(user_input)
    if user_input == "bye": break

socket.close()
server_socket.close()