import idaapi
import ida_bytes
import ida_frame
import ida_struct
import idc
import idautils

I_JUMPS = ['jmp', 'je', 'jne', 'jg', 'ja', 'jae', 'jl', 'jle', 'jb', 'jbe', 'jz', 'jnz', 'js', 'jns', 'jc', 'jnc', 'jo', 'jno', 'jcxz', 'jecxz', 'jrcxz']

# TODO: Create a class that will hold XRefs to data/rodata
# The class will include information about the places where the the data has
# been cross-referenced.

class Loop:
    def __init__(self, startea: int, endea: int) -> None:
        self.startAddr = startea
        self.endAddr = endea


class XRef:
    def __init__(self, address: int, crossref: int, type: bool) -> None:
        self.address = address
        self.ref_pointer = crossref
        self.type = type


# class Location:
#     def __init__(self, address: int) -> None:
#         self.address = address
#         self.called_from = []


class Function:
    def __init__(self, address: int) -> None:
        self.f_addr = address
        self.f_loops = []
        self.f_xrefs = []
        self.f_locations = 0
        self.f_callers = []
        self.f_callees = []

    def add_loop(self, loop: Loop) -> None:
        self.f_loops.append(loop)

    def add_xref(self, xref: XRef) -> None:
        self.f_xrefs.append(xref)

    def add_caller(self, address: int) -> None:
        self.f_callers.append(address)

    def add_callee(self, address: int) -> None:
        self.f_callees.append(address)


def contains_jump(instruction: str) -> bool:
    if any(jump in instruction for jump in I_JUMPS):
        return True
    return False

def count_loc(start: int, end: int) -> tuple[int, int]:
    cnt = 0
    cntj = 0
    addr = start
    while (addr < end) and (addr != end):
        instruction = idc.GetDisasm(addr)
        if "loc_" in instruction:
            cnt += 1
        if contains_jump(instruction):
            cntj += 1
        addr = idc.next_addr(addr)

    return (cnt, cntj)


def is_subroutine(loc: str) -> bool:
    if loc.lower().find('sub') is not -1:
        return True
    return False


def is_location(loc: str) -> bool:
    if loc.lower().find('loc') is not -1:
        return True
    return False

##
#  Check if string is_location beforehand
def get_loc_address(loc: str) -> int:
    return int('0x' + loc[loc.lower().find("loc_") + 4:], 16)


def check_address_in_segment(addr: int) -> bool:
    pass

TEXT_S = idaapi.get_segm_by_name(".text")
# (RODATA_START, RODATA_END) = idaapi.get_segm_by_name
addr = idc.get_next_func(TEXT_S.start_ea)


# Loops through subroutines

while addr is not idc.BADADDR:
    f_name = idc.get_func_name(addr)
    f_size = idc.get_func_attr(addr, idc.FUNCATTR_END) - addr - 4
    frame_id = ida_frame.get_frame(addr)
    f_frame_size = ida_struct.get_struc_size(frame_id)
    (f_locs, f_jumps) = count_loc(addr, addr + f_size)

    # Subroutine analysis
    branching_cnt = 0
    instruction = addr
    func = Function(addr)
    while instruction is not idc.BADADDR and instruction < idc.find_func_end(addr):
        op = idc.print_insn_mnem(instruction)
        # Adrian's metric
        if len(op) > 0 and op[0] == 'b':
            branching_cnt += 1
        elif len(op) > 0 and op == 'mov' and idc.print_operand(instruction, 0) == 'pc':
            branching_cnt += 1

        if contains_jump(instruction):
            # TODO check if jumped address is lower than current address
            # If so, this is a loop
            param = idc.print_operand(instruction)
            if is_location(param):
                jump_address = get_loc_address(param)
                if jump_address < instruction and idc.get_func_name(jump_address) == f_name:
                    func.add_loop(Loop(jump_address, instruction))

        instruction = idc.next_head(instruction)

    print("Function %s at %08x: size %d, frame %d, locs %d, jumps %d." % (f_name, addr, f_size, f_frame_size, f_locs, f_jumps))

    addr = idc.get_next_func(addr)

print("END")
