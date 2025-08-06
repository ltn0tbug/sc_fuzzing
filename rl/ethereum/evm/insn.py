from .opcode import OP_NAME

REVERSE_OP_NAME = {v: k for k, v in OP_NAME.items()}

class Instruction:

    def __init__(self, *args, **kwargs):
        self.contract = kwargs['contract']
        self.pc = kwargs['pc'] # program count, the count in bytecode
        self.arg = kwargs['arg'] # only PUSH has args
        self.op_name = kwargs['op'] # the hex of opcode
        if str(self.op_name).find("UNKNOWN") != -1 or str(self.op_name).find("INVALID") != -1:
            self.op = 0
        else:
            self.op = REVERSE_OP_NAME[self.op_name] # the name of opcode
        self.idx = None # the line of insn, one line is that (opcode,arg)
        self.states = set()


    def is_push(self):
        return 0x60 <= self.op <= 0x7f


    def __str__(self):
        s = '{} {} {}'.format(self.idx, format(self.pc, '02x'), self.op_name)
        if self.is_push():
            arg_val = int(self.arg, 16) 
            s += ' {}'.format(format(arg_val, '02x'))

        return s


    def add_state(self, new_state):
        self.states.add(new_state)
