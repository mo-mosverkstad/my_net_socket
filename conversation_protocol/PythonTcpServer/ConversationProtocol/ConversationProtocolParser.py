from .ConversationProtocolDefinition import *
from .ProtocolParser import *

class ConversationProtocolParser(object):
    def __init__(self, version:int):
        self.version = version
        self.definition = ConversationProtocolDefinition(version)

    def encode(self, cmd_id:int, prm_values:list):
        prm_ids = self.definition.get_prm_list(cmd_id)
        prms = zip(prm_ids, prm_values)
        return ProtocolParser.encode(self.version, cmd_id, prms)

    def decode(self, payload:bytearray):
        recv_version, cmd_id, prm_id_values = ProtocolParser.decode(payload)
        recv_definition = ConversationProtocolDefinition(recv_version)
        prm_name_values = []
        for prm in prm_id_values:
            prm_id, prm_value = prm
            prm_name_values.append((recv_definition.get_prm_name(prm_id), prm_value))
        return recv_definition.get_cmd_name(cmd_id), prm_name_values
