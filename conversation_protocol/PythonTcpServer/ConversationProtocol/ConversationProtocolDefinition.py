CMD_CALL_ID = 1
CMD_ANSW_ID = 2
CMD_REJT_ID = 3
CMD_REQU_ID = 4
CMD_RESP_ID = 5
CMD_RELS_ID = 6
CMD_RELD_ID = 7
CMD_ERRR_ID = 8

CMD_CALL_NAME = 'CALL'
CMD_ANSW_NAME = 'ANSW'
CMD_REJT_NAME = 'REJT'
CMD_REQU_NAME = 'REQU'
CMD_RESP_NAME = 'RESP'
CMD_RELS_NAME = 'RELS'
CMD_RELD_NAME = 'RELD'
CMD_ERRR_NAME = 'ERRR'

PRM_CLNM_ID = 1
PRM_SVNM_ID = 2
PRM_ERRR_ID = 3
PRM_DATA_ID = 4

PRM_CLNM_NAME = 'CLIENT_NAME'
PRM_SVNM_NAME = 'SERVER_NAME'
PRM_ERRR_NAME = 'ERROR_REASON'
PRM_DATA_NAME = 'DATA'

COMMANDS_V1 = [( (CMD_CALL_ID, CMD_CALL_NAME), [(PRM_CLNM_ID, PRM_CLNM_NAME)] ),
               ( (CMD_ANSW_ID, CMD_ANSW_NAME), [(PRM_SVNM_ID, PRM_SVNM_NAME)] ),
               ( (CMD_REJT_ID, CMD_REJT_NAME), [(PRM_ERRR_ID, PRM_ERRR_NAME)] ),
               ( (CMD_REQU_ID, CMD_REQU_NAME), [(PRM_DATA_ID, PRM_DATA_NAME)] ),
               ( (CMD_RESP_ID, CMD_RESP_NAME), [(PRM_DATA_ID, PRM_DATA_NAME)] ),
               ( (CMD_RELS_ID, CMD_RELS_NAME), []                             ),
               ( (CMD_RELD_ID, CMD_RELD_NAME), []                             ),
               ( (CMD_ERRR_ID, CMD_ERRR_NAME), [(PRM_ERRR_ID, PRM_ERRR_NAME)] ),
               ]

VERSION_V1 = 1
COMMANDS = {VERSION_V1: COMMANDS_V1}

class ConversationProtocolDefinition(object):
    def __init__(self, version):
        self.version = version
        self.commands = COMMANDS[version]
        self.cmd_id_name_dict = {}
        self.cmd_name_id_dict = {}
        self.cmd_prm_dict = {}
        self.prm_id_name_dict = {}
        self.prm_name_id_dict = {}
        self.__generate_dict()

    def __generate_dict(self):
        for cmd_prm in self.commands:
            (cmd_id, cmd_name), prms = cmd_prm
            self.cmd_id_name_dict[cmd_id] = cmd_name
            self.cmd_name_id_dict[cmd_name] = cmd_id
            self.cmd_prm_dict[cmd_id] = []
            for prm in prms:
                prm_id, prm_name = prm
                self.cmd_prm_dict[cmd_id].append(prm_id)
                if not prm_id in self.prm_id_name_dict:
                    self.prm_id_name_dict[prm_id] = prm_name
                    self.prm_name_id_dict[prm_name] = prm_id

    def get_cmd_id(self, cmd_name):
        return self.cmd_name_id_dict[cmd_name]

    def get_cmd_name(self, cmd_id):
        return self.cmd_id_name_dict[cmd_id]

    def get_prm_id(self, prm_name):
        return self.prm_name_id_dict[prm_name]

    def get_prm_name(self, prm_id):
        return self.prm_id_name_dict[prm_id]

    def get_prm_list(self, cmd_id):
        return self.cmd_prm_dict[cmd_id]