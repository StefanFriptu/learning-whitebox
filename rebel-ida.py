import idaapi
import ida_frame
import ida_struct
import idc

I_JUMPS = ['jmp', 'je', 'jne', 'jg', 'ja', 'jae', 'jl', 'jle', 'jb', 'jbe', 'jz', 'jnz', 'js', 'jns', 'jc', 'jnc', 'jo', 'jno', 'jcxz', 'jecxz', 'jrcxz']

class XMap 

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


text_segment = idaapi.get_segm_by_name(".text")
addr = idc.get_next_func(text_segment.start_ea)

# Loops through subroutines
while addr is not idc.BADADDR:
    f_name = idc.get_func_name(addr)
    f_size = idc.get_func_attr(addr, idc.FUNCATTR_END) - addr - 4
    frame_id = ida_frame.get_frame(addr)
    f_frame_size = ida_struct.get_struc_size(frame_id)
    (f_locs, f_jumps) = count_loc(addr, addr + f_size)


    # Subroutine analysis
    branching_cnt = 0
    instruction = idc.next_head(addr)
    while instruction is not idc.BADADDR and instruction < idc.find_func_end(addr):
        op = idc.print_insn_mnem(instruction)
        if len(op) > 0 and op[0] == 'b':
            branching_cnt += 1
        elif len(op) > 0 and op == 'mov' and idc.print_operand(instruction, 0) == 'pc':
            branching_cnt += 1

        if contains_jump(instruction):
            # TODO check if jumped address 

        instruction = idc.next_head(instruction)

    print("Function %s at %08x: size %d, frame %d, locs %d, jumps %d." % (f_name, addr, f_size, f_frame_size, f_locs, f_jumps))

    addr = idc.get_next_func(addr)

print("END")
