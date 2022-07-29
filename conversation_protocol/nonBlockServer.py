import socket
import select

server_socket = socket.socket()
server_socket.bind(('0.0.0.0', 1337))
server_socket.listen()

inputs = [server_socket, ]
outputs = []
message_dict = {}

while True:
    readable, writable, exceptional = select.select(inputs, outputs, inputs, 1)
    #print('Be listening to the sockets', inputs)
    print(readable)
    for readable_socket in readable:
        if readable_socket == server_socket:
            socket, address = readable_socket.accept()
            inputs.append(socket)
            message_dict[socket] = []
        else:
            # client socket
            try:
                data_bytes = readable_socket.recv(1024)
            except Exception as ex:
                # if client terminate
                inputs.remove(readable_socket)
            else:
                data_str = str(data_bytes, encoding='utf-8')
                message_dict[readable_socket].append(data_str)
                outputs.append(readable_socket)

    for socket in writable:
        recv_str = message_dict[socket][0]
        del message_dict[socket][0]
        socket.sendall(bytes(recv_str+': ok', encoding='utf-8'))
        outputs.remove(socket)

    for socket in exceptional:
        inputs.remove(socket)