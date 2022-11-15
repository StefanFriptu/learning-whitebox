import idaapi
import ida_frame
import ida_struct
import idc

text_segment = idaapi.get_segm_by_name(".text")
addr = idc.get_next_func(text_segment.start_ea)

while addr is not idc.BADADDR:
    f_name = idc.get_func_name(addr)
    f_size = idc.get_func_attr(addr, idc.FUNCATTR_END) - addr - 4
    frame_id = ida_frame.get_frame(addr)
    f_frame_size = ida_struct.get_struc_size(frame_id)

    print("Function %s at %08x: size %d, frame %d." % (f_name, addr, f_size, f_frame_size))

    addr = idc.get_next_func(addr)

print("END")
