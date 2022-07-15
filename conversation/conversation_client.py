from my_socket import Socket

socket = Socket ('127.0.0.1', 1337)

while True:
    user_input = input(">")
    socket.send(user_input)
    if user_input == "bye": break
    server_message = socket.receive()
    if server_message == "bye": break

socket.close()