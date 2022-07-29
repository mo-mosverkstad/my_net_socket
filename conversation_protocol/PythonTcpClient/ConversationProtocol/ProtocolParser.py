class ProtocolParser():

    @staticmethod
    def encode_command(payload:bytearray, version:int, command:int) -> bytearray:
        payload.append(0b00000000 | ((version & 0b00001111) << 4) | ((command & 0b00001111) << 0))
        return payload

    @staticmethod
    def encode_parameter(payload:bytearray, parameter_id:int, parameter_value:str) -> bytearray:
        payload.append(0b00000000 | ((parameter_id & 0b11111111) << 0))
        payload.append(len(parameter_value))
        payload.extend(map(ord, parameter_value))
        return payload

    @staticmethod
    def encode(version:int, command:int, parameters:list) -> bytearray:
        payload = ProtocolParser.encode_command(bytearray(), version, command)
        for parameter in parameters:
            parameter_id, parameter_value = parameter
            payload = ProtocolParser.encode_parameter(payload, parameter_id, parameter_value)
        return payload

    @staticmethod
    def decode_command(payload:bytearray):
        version = (payload[0] & 0b11110000) >> 4
        command = (payload[0] & 0b00001111) >> 0
        return version, command

    @staticmethod
    def decode_parameter(payload:bytearray, start_index: int):
        parameter_id = payload[start_index]
        parameter_length = payload[start_index + 1]
        parameter_value = payload[start_index + 2 : start_index + 2 + parameter_length]
        return parameter_id, parameter_value, start_index + 2 + parameter_length

    @staticmethod
    def decode(payload:bytearray):
        version, command = ProtocolParser.decode_command(payload)
        index = 1
        parameters = []
        while (index < len(payload)):
            parameter_id, parameter_value, index = ProtocolParser.decode_parameter(payload, index)
            parameters.append((parameter_id, parameter_value))
        return version, command, parameters

