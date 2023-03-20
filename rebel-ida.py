from enum import Enum
from statistics import fmean, variance, stdev
from collections import Counter
from math import log

import csv
import idaapi
import ida_frame
import ida_struct
import idc
import idautils
import os

CSV_HEADER = ['function name', 'size', 'frame size', 'internal locations', 'jumps', 'detected loops', 'code xrefs', 'data xrefs', 'xrefs to high entropy area', 'bitwise operations', 'max consecutive movs', 'function entropy']

# I_* list to be passed to contains_instr func
I_JUMPS = ['jmp', 'je', 'jne', 'jg', 'ja', 'jae', 'jl', 'jle', 'jb', 'jbe', 'jz', 'jnz', 'js', 'jns', 'jc', 'jnc', 'jo', 'jno', 'jcxz', 'jecxz', 'jrcxz']
I_LOGICAL = ['and', 'or', 'xor', 'test', 'not']

# The interesting program segments for this script
S_DATA   = ".data"
S_TEXT   = ".text"
S_RODATA = ".rodata"
S_BSS    = '.bss'

#TODO: Create a class that will hold XRefs to data/rodata
# The class will include information about the places where the the data has
# been cross-referenced.

class Loop:
    def __init__(self, startea: int, endea: int) -> None:
        self.startAddr = startea
        self.endAddr = endea


class XRef_Type(Enum):
    CODE = 1
    DATA = 2


class XRef:
    def __init__(self, address: int, crossref: int, type: XRef_Type) -> None:
        self.address = address
        if not isinstance(crossref, int):
            print("WARNING: Expected integer as cross reference, got %s." % str(crossref))
        self.to_address = crossref
        self.type = type
        self.entropy = None

    #TODO: how to tune block_size? or how to end search for better entropy accuracy
    def calc_xref_entropy(self, block_size: int = 8192):
        temp = data_from_to(self.to_address, self.to_address + block_size)
        self.entropy = entropy(temp)

    def prettyprint(self):
        print("XRef at %08x to %08x as %s." % (self.address, self.to_address, ("CODE" if self.type == XRef_Type.CODE else "DATA")))

# Application ID AA00BUESN9
ref_dict = {}

class Function:
    def __init__(self, address: int) -> None:
        self.f_name = ""
        self.f_addr = address
        self.f_end = idc.find_func_end(address)
        self.f_loops = []
        self.f_xrefs = []
        self.f_xrefs_high_entropy = 0
        self.f_locations = 0
        self.f_jumps = 0
        self.f_callers = []
        self.f_callees = []
        self.f_bitops = 0
        self.f_frame_size = ida_struct.get_struc_size(ida_frame.get_frame(address))
        self.f_max_consecutive_movs = 0
        self.f_adrian_branch_cnt = 0
        self.f_entropy = calc_mean_data_entropy(data_from_to(self.f_addr, self.f_end), step_size=16)

    def add_loop(self, loop: Loop) -> None:
        self.f_loops.append(loop)

    def add_xref(self, xref: XRef) -> None:
        # if xref.to_address in ref_dict.keys():
        #    xref.entropy = ref_dict[xref.to_address]
            ## print("XRef to %08x exists." % (xref.to_address))
        # else:
        #    xref.calc_xref_entropy()
        #    ref_dict[xref.to_address] = xref.entropy
            ## print("Processing XRef to %08x." % (xref.to_address))

        self.f_xrefs.append(xref)

    def add_caller(self, address: int) -> None:
        self.f_callers.append(address)

    def add_callee(self, address: int) -> None:
        self.f_callees.append(address)

    def has_addr(self, address: int) -> bool:
        if address >= self.f_addr and addr <= self.f_end:
            return True
        return False

    def calculate_entropy (self) -> float:
        data = data_from_to(self.f_addr, self.f_end)
        return entropy(data)

    def getCsvLine(self) -> list:
        line = []
        cxrefs = list(xref.entropy for xref in self.f_xrefs if xref.type == XRef_Type.CODE)
        dxrefs = list(xref.entropy for xref in self.f_xrefs if xref.type == XRef_Type.DATA)
        line.append(idaapi.get_func_name(self.f_addr)) # for labeling, drop in preprocessing
        line.append(self.f_end - self.f_addr)
        line.append(self.f_frame_size)
        line.append(self.f_locations)
        line.append(self.f_jumps)
        line.append(len(self.f_loops))
        line.append(len(cxrefs))
        line.append(len(dxrefs))
        line.append(self.f_xrefs_high_entropy)
        line.append(self.f_bitops)
        line.append(self.f_max_consecutive_movs)
        line.append(round(self.f_entropy, 3))
        return line

    def prettyprint(self) -> None:
        cxrefs = list(xref.entropy for xref in self.f_xrefs if xref.type == XRef_Type.CODE)
        dxrefs = list(xref.entropy for xref in self.f_xrefs if xref.type == XRef_Type.DATA)

        print("Function %s at %08x:" % (idc.get_func_name(self.f_addr), self.f_addr))
        print("[*] size: %d" % (self.f_end - self.f_addr))
        print("[*] frame size: %d" % self.f_frame_size)
        print("[*] internal locations: %d" % self.f_locations)
        print("[*] jumps: %d" % self.f_jumps)
        print("[*] detected loops: %d" % len(self.f_loops))
        print("[*] code xrefs: %d" % len(cxrefs))
        print("[*] data xrefs: %d" % len(dxrefs))
        print("[*] xrefs to high entropy area: %d" % self.f_xrefs_high_entropy)
        print("[*] bitwise operations: %d" % (self.f_bitops))
        print("[*] adrian branching index: %d" % self.f_adrian_branch_cnt) # not added into csv
        print("[*] max consecutive movs: %d" % self.f_max_consecutive_movs)
        print("[*] func entropy: %3f" % self.f_entropy)
        # if len(dxrefs) > 0:
        #     print(f"[*] data xrefs mean entropy: {fmean(dxrefs)}")
        # if len(cxrefs) > 0:
        #     print(f"[*] code xrefs mean entropy: {fmean(cxrefs)}")
        print('\n')
        # for xref in self.f_xrefs:
        #     if xref.type == XRef_Type.DATA:
        #         xref.prettyprint()


class Segment:
    def __init__(self, seg_name: str) -> None:
        segm = idaapi.get_segm_by_name(seg_name)
        self.start_ea = segm.start_ea
        self.end_ea = segm.end_ea
        self.entropy = 0.0
        self.variance = 0.0
        self.stdd = 0.0

    def has_addr(self, addr: int) -> bool:
        if addr >= self.start_ea and addr <= self.end_ea:
            return True
        return False


def contains_instr(instruction: str, what: list) -> bool:
    # Sometimes integers are passed and program exits with error
    if any(instr in str(instruction) for instr in what):
        return True
    return False


def count_loc_jumps(start: int, end: int) -> tuple[int, int]:
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
    S_RODATA: Segment(S_RODATA),
    S_BSS: Segment(S_BSS),
}

def entropy(data: bytes) -> float:
    if len(data) == 0:
        return 0.0
    occurances = Counter(bytearray(data))
    calc_entropy = 0
    for x in occurances.values():
        p_x = float(x) / len(data)
        calc_entropy -= p_x * log(p_x, 2)
    return calc_entropy


def data_from_to(start_ea: int, end_ea: int, fill = '\x00') -> bytes:
    curr_ea = start_ea
    ret = ""
    while curr_ea < end_ea:
        if idaapi.is_loaded(curr_ea):
            ret += chr(idaapi.get_byte(curr_ea))
        else:
            ret += fill
        curr_ea += 1
    return bytes(ret, 'latin1')


def calc_data_entropy(data: bytes, block_size: int = 256, step_size: int = 128) -> list:
    entropies = []
    for block in (data[x:block_size + x] for x in range (0, len(data) - block_size, step_size)):
        entropies.append(entropy(block))
    return entropies


def calc_mean_data_entropy(data: bytes, block_size: int = 256, step_size: int = 128) -> float:
    entropies = calc_data_entropy(data, block_size, step_size)
    if len(entropies) == 0:
        return 0.0
    return fmean(entropies)


def calc_segments_entropy(block_size: int = 256, step_size: int = 128) -> float:
    entropies_over_segments = []
    for (key, segment) in segments.items():
        data = data_from_to(segment.start_ea, segment.end_ea)
        # Calculate entropy per block
        entropies = []
        for block in (data[x:block_size + x] for x in range (0, len(data) - block_size, step_size)):
            entropies.append(entropy(block))
            entropies_over_segments.append(entropy(block))

        if len(entropies) > 0:
            segment.entropy = fmean(entropies)
            segment.variance = variance(entropies)
            segment.stdd = stdev(entropies)
            print(f"Segment {key}: ------------")
            print(f"[*] mean entropy: {segment.entropy}")
            print(f"[*] std dev: {segment.stdd}")
            print(f"[*] variance: {segment.variance}")

    print(f"Binary mean entropy: {fmean(entropies_over_segments)}")
    print(f"Binary std dev: {stdev(entropies_over_segments)}")
    print(f"Binary variance: {variance(entropies_over_segments)}")
    return fmean(entropies_over_segments)


def follow_xref(ref):
    refs = list(idautils.DataRefsFrom(ref))
    if (len(refs) > 0) and ref != refs[0]:
        # print("Following %08x" % (refs[0]))
        return follow_xref(refs[0])
    else:
        return ref

# CSV specifics
DATASET_FILE = '/home/stefan/Work/hidden-rice/obfuscated_dataset.csv'
target_file = open(DATASET_FILE, 'a', encoding='utf-8')
target_writer = csv.writer(target_file)
if os.path.getsize(DATASET_FILE) == 0:
    target_writer.writerow(CSV_HEADER)

# Analysis
addr = idc.get_next_func(segments[S_TEXT].start_ea)
# Loops through subroutines
while addr != idc.BADADDR:
    func = Function(addr)
    f_name = idc.get_func_name(addr)
    f_size = idc.get_func_attr(addr, idc.FUNCATTR_END) - addr - 4
    frame_id = ida_frame.get_frame(addr)
    f_frame_size = ida_struct.get_struc_size(frame_id)
    (func.f_locations, func.f_jumps) = count_loc_jumps(addr, addr + f_size)
    func.f_name = f_name

    # Subroutine analysis
    branching_cnt = 0
    movs = 0
    instruction = addr
    while instruction != idc.BADADDR and instruction < idc.find_func_end(addr):

        op = idc.print_insn_mnem(instruction).lower()
        # Adrian's metric
        if len(op) > 0 and op[0] == 'b':
            branching_cnt += 1
        elif len(op) > 0 and op == 'mov' and idc.print_operand(instruction, 0).lower() == 'pc':
            branching_cnt += 1

        # Consecutive mov instructions used for initializations (i.e. tables)
        if len(op) > 0 and op == 'mov':
            movs += 1
        else:
            if movs > func.f_max_consecutive_movs:
                func.f_max_consecutive_movs = movs
            movs = 0

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
                # func.add_xref(cxref)

        if any(idautils.DataRefsFrom(instruction)):
            for dref in idautils.DataRefsFrom(instruction):
                xref = None
                if segments[S_TEXT].has_addr(dref) and not func.has_addr(dref):
                    xref = XRef(instruction, dref, XRef_Type.CODE)
                elif segments[S_DATA].has_addr(dref) or segments[S_RODATA].has_addr(dref) or segments[S_BSS].has_addr(dref):
                    # print("Following %08x..." % (instruction))
                    xref = XRef(instruction, follow_xref(dref), XRef_Type.DATA)
                if xref is not None:
                    func.add_xref(xref)

        instruction = idc.next_head(instruction)
    func.f_adrian_branch_cnt = branching_cnt
    ref_dict[func.f_name] = func
    # print("Function %s at %08x: sizeimport typing %d, frame %d, locs %d, jumps %d." % (f_name, addr, f_size, f_frame_size, f_locs, f_jumps))
    addr = idc.get_next_func(addr)

print("\n\n")
binary_mean_entropy = calc_segments_entropy()
ref_dict_keys = ref_dict.keys()

for (key_addr, func) in ref_dict.items():
    for xref in func.f_xrefs:
        func_holding_xref = idc.get_func_name(xref.to_address)
        if func_holding_xref:
            if func_holding_xref in ref_dict_keys:
                if ref_dict[func_holding_xref].f_entropy > binary_mean_entropy:
                    func.f_xrefs_high_entropy += 1
        else:
            for (key, segment) in segments.items():
                if segment.has_addr(xref.to_address):
                    if segment.entropy > binary_mean_entropy:
                        func.f_xrefs_high_entropy += 1
    func.prettyprint()
    target_writer.writerow(func.getCsvLine())

target_file.close()
print("END")
