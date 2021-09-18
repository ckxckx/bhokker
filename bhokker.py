#coding:utf-8

#  hook_addr : int + shellcode : str
# limitation : only linux elf on amd64 work well

import idautils
import ida_lines
import idc
import idaapi
import ida_bytes
import struct
from keystone import *

import archinfo


info=idaapi.get_inf_structure()

if info.is_32bit():
    pass
else:
    raise Exception("32bit not support yet")


# struct.unpack()


class PatchSpot:
    segment_info={}
    range_start_ea=None
    range_end_ea = None
    range_size = 0
    patch_start = None

found = False
for s in idautils.Segments():
    seg = idaapi.getseg(s)
    the_segname= idc.get_segm_name(s)
    print(the_segname)
    # 代码风格习惯保持
    if the_segname != ".eh_frame":
        continue
    found=True
    pspot=PatchSpot()
    pspot.range_start_ea = seg.start_ea
    pspot.range_end_ea = seg.end_ea
    pspot.range_size = pspot.range_end_ea-pspot.range_start_ea
    pspot.segment_info={"type":"existed","name":the_segname}
    pspot.patch_start = pspot.range_start_ea+0x20
    break

# 以后打代码，养成这个习惯，if语句里面放错误处理，主逻辑尽可能在if路径外
if not found:
    raise Exception("not found supposed segment")



def patch_before_addr_at_spot(content: bytes, addr: int,spot:PatchSpot):
    # content: bytes
    # 1.先计算长跳转需要占据字节个数
    # 2. 计算长跳转patch会影响的指令个数
    # 3. 将被影响的指令对应的字节摘出
    # 4. content+influenced intruction bytes+jump back
    # 5. 返回patch_info_dict = {"ea1":b"xxxx", "ea2": b"xxx"}

    #1
    oprand = str(spot.patch_start-addr)
    opcode = "jmp"
    CODE = opcode+" "+oprand+";"

    
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm(CODE)
    print("%s = %s (number of statements: %u)" %(CODE, encoding, count))
    patch_length = len(encoding)
    hook_bytes = bytes(encoding)

    
    #2
    influenced_insn=[]
    accumulate_length = 0
    insn_ea = addr
    while True:
        insn = idaapi.insn_t()
        length = idaapi.decode_insn(insn, insn_ea)
        influenced_insn.append(insn_ea)
        accumulate_length += length
        insn_ea += length
        if accumulate_length>=patch_length:
            break
    hook_bytes += b'\x90'*(accumulate_length-patch_length)

    #3
    repair_bytes=ida_bytes.get_bytes(addr,accumulate_length)

    #4
    jumpback_ea = spot.patch_start+len(content)+len(repair_bytes)
    offset = addr + accumulate_length - jumpback_ea
    jumpbackcode = "jmp %s" % str(offset)
    jumpback_encoding, count = ks.asm(jumpbackcode)
    print("%s = %s (number of statements: %u)" %(jumpbackcode, jumpback_encoding, count))
    patch_length = len(jumpback_encoding)
    jump_back_bytes = bytes(jumpback_encoding)
    inject_bytes = content + repair_bytes + jump_back_bytes
        
    #5
    patch_info_dict = {addr:hook_bytes,spot.patch_start:inject_bytes}
    return patch_info_dict



# ret=patch_before_addr_at_spot(b"\x90\x90\x90",0x6CA,pspot)

revertpatch_info_dict = {}
def commit_patch(patch_info_dict,revertpatch_info_dict=None):
    for key in patch_info_dict:
        thebytes=patch_info_dict[key]
        if revertpatch_info_dict:
            revertpatch_info_dict[key]=ida_bytes.get_bytes(key,len(thebytes))
        print("patch at %s with %d bytes"%(hex(key),len(thebytes)))
        for idx,bt in enumerate(thebytes):
            ea = key+idx
            ida_bytes.patch_byte(ea,bt)
        

# commit_patch(patch_info_dict,revertpatch_info_dict)

shellcode_asm = '''
/*keep parameters*/
push rdi
push rsi
push rax
push rdx

/* write(fd=1, buf='aaaa', n=10) */
/* push b'aaaa\\x00' */    
push 0x61616161
mov rsi, rsp
push 1
pop rdi    
push 9 
/*mov edx, '\\n' */
pop rdx
inc edx    
/* call write() */
push 1 /* 1 */
pop rax
syscall
pop rax

pop rdx
pop rax
pop rsi
pop rdi
'''

ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, count = ks.asm(shellcode_asm)
content = bytes(encoding)


hook_addr = 0x6CA
ret=patch_before_addr_at_spot(content,hook_addr,pspot)
commit_patch(ret,revertpatch_info_dict)

