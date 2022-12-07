import idaapi
import ida_frame
import ida_struct
import idc
import idautils


# I_* list to be passed to contains_instr func
I_JUMPS = ['jmp', 'je', 'jne', 'jg', 'ja', 'jae', 'jl', 'jle', 'jb', 'jbe', 'jz', 'jnz', 'js', 'jns', 'jc', 'jnc', 'jo', 'jno', 'jcxz', 'jecxz', 'jrcxz']
I_LOGICAL = ['and', 'or', 'xor', 'test', 'not']

# The interesting program segments for this script
S_DATA   = ".data"
S_TEXT   = ".text"
S_RODATA = ".rodata"

# TODO: Create a class that will hold XRefs to data/rodata
# The class will include information about the places where the the data has
# been cross-referenced.

class Loop:
    def __init__(self, startea: int, endea: int) -> None:
        self.startAddr = startea
        self.endAddr = endea


class XRef_Type:
    CODE = 1
    DATA = 2



class XRef:
    def __init__(self, address: int, crossref: int, type: XRef_Type) -> None:
        self.address = address
        if not isinstance(crossref, int):
            print("WARNING: Expected integer as cross reference, got %s." % str(crossref))
        self.to_address = crossref
        self.type = type

    def prettyprint(self):
        print("XRef at %08x to %08x as %s." % (self.address, self.to_address, ("CODE" if self.type == XRef_Type.CODE else "DATA")))


class Function:
    def __init__(self, address: int) -> None:
        self.f_addr = address
        self.f_end = idc.find_func_end(address)
        self.f_loops = []
        self.f_xrefs = []
        self.f_locations = 0
        self.f_jumps = 0
        self.f_callers = []
        self.f_callees = []
        self.f_bitops = 0
        self.f_frame_size = ida_struct.get_struc_size(ida_frame.get_frame(address))
        self.f_adrian_branch_cnt = 0

    def add_loop(self, loop: Loop) -> None:
        self.f_loops.append(loop)

    def add_xref(self, xref: XRef) -> None:
        self.f_xrefs.append(xref)

    def add_caller(self, address: int) -> None:
        self.f_callers.append(address)

    def add_callee(self, address: int) -> None:
        self.f_callees.append(address)

    def has_addr(self, address: int) -> bool:
        if address >= self.f_addr and addr <= self.f_end:
            return True
        return False

    def prettyprint(self) -> None:
        print("Function %s at %08x:" % (idc.get_func_name(self.f_addr), self.f_addr))
        print("[*] size: %d" % (self.f_end - self.f_addr))
        print("[*] frame size: %d" % self.f_frame_size)
        print("[*] internal locations: %d" % self.f_locations)
        print("[*] jumps: %d" % self.f_jumps)
        print("[*] detected loops: %d" % len(self.f_loops))
        print("[*] code xrefs: %d" % len(list(xref for xref in self.f_xrefs if xref.type == XRef_Type.CODE)))
        print("[*] data xrefs: %d" % len(list(xref for xref in self.f_xrefs if xref.type == XRef_Type.DATA)))
        print("[*] bitwise operations: %d" % (self.f_bitops))
        print("[*] adrian branching index: %d\n" % self.f_adrian_branch_cnt)
        # for xref in self.f_xrefs:
        #     xref.prettyprint()


class Segment:
    def __init__(self, seg_name: str) -> None:
        segm = idaapi.get_segm_by_name(seg_name)
        self.start_ea = segm.start_ea
        self.end_ea = segm.end_ea

    def has_addr(self, addr: int) -> bool:
        if addr >= self.start_ea and addr <= self.end_ea:
            return True
        return False


def contains_instr(instruction: str, what: list) -> bool:
    # Sometimes integers are passed and program exits with error
    if any(instr in str(instruction) for instr in what):
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
        if contains_instr(instruction, I_JUMPS):
            cntj += 1
        addr = idc.next_addr(addr)

    return (cnt, cntj)

def is_subroutine(loc: str) -> bool:
    if loc.lower().find('sub') != -1:
        return True
    return False

def is_location(loc: str) -> bool:
    if loc.lower().find('loc') != -1:
        return True
    return False

# Check if string is_location beforehand
def get_loc_address(loc: str) -> int:
    strip_addr = loc[loc.lower().find("loc") + 3:]
    if strip_addr.startswith('ret_'):
        return int('0x' + strip_addr[strip_addr.lower().find("ret_") + 4:], 16)
    return int('0x' + loc[loc.lower().find("loc_") + 4:], 16)


segments = {
    S_DATA: Segment(S_DATA),
    S_TEXT: Segment(S_TEXT),
    S_RODATA: Segment(S_RODATA)
}

addr = idc.get_next_func(segments[S_TEXT].start_ea)
# Loops through subroutines
while addr != idc.BADADDR:

    func = Function(addr)

    f_name = idc.get_func_name(addr)
    f_size = idc.get_func_attr(addr, idc.FUNCATTR_END) - addr - 4
    frame_id = ida_frame.get_frame(addr)
    f_frame_size = ida_struct.get_struc_size(frame_id)
    (func.f_locations, func.f_jumps) = count_loc(addr, addr + f_size)

    # Subroutine analysis
    branching_cnt = 0
    instruction = addr
    while instruction != idc.BADADDR and instruction < idc.find_func_end(addr):

        op = idc.print_insn_mnem(instruction).lower()
        # Adrian's metric
        if len(op) > 0 and op[0] == 'b':
            branching_cnt += 1
        elif len(op) > 0 and op == 'mov' and idc.print_operand(instruction, 0).lower() == 'pc':
            branching_cnt += 1

        # Check is loop
        if contains_instr(op, I_JUMPS):
            param = idc.print_operand(instruction, 0)
            if is_location(param):
                jump_address = get_loc_address(param)
                if jump_address < instruction and idc.get_func_name(jump_address) == f_name:
                    func.add_loop(Loop(jump_address, instruction))

        # Count bitwise operations
        if contains_instr(op, I_LOGICAL):
            func.f_bitops += 1

        # Process XRef - Code reference
        if any(idautils.XrefsFrom(instruction, 0)):
            for ref in idautils.XrefsFrom(instruction, 0):
                cxref = XRef(instruction, ref.to, XRef_Type.CODE)
                func.add_xref(cxref)

        if any(idautils.DataRefsFrom(instruction)):
            for dref in idautils.DataRefsFrom(instruction):
                if segments[S_TEXT].has_addr(dref) and not func.has_addr(dref):
                    cxref = XRef(instruction, dref, XRef_Type.CODE)
                    func.add_xref(cxref)
                elif segments[S_DATA].has_addr(dref) or segments[S_RODATA].has_addr(dref):
                    dxref = XRef(instruction, dref, XRef_Type.DATA)
                    func.add_xref(dxref)

        instruction = idc.next_head(instruction)
    func.f_adrian_branch_cnt = branching_cnt
    func.prettyprint()
    # print("Function %s at %08x: size %d, frame %d, locs %d, jumps %d." % (f_name, addr, f_size, f_frame_size, f_locs, f_jumps))

    addr = idc.get_next_func(addr)

print("END")
