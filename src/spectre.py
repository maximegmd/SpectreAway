from idautils import *
from idaapi import *
from idc import *
from collections import OrderedDict
import sys


def trampoline():
    with open('calls.txt', 'w') as f:
        oldout = sys.stdout
        sys.stdout = f
        for segea in Segments():
            for funcea in Functions(segea, SegEnd(segea)):
                functionName = GetFunctionName(funcea)
                disasm = GetDisasm(funcea)
                if disasm.startswith("jmp     sub_14"):
                    for ref in XrefsTo(funcea):
                        ref_disasm = GetDisasm(ref.frm)
                        if ref_disasm.startswith("call"):
                            jmp_addr = GetOperandValue(funcea, 0)
                            jmp_diasm = GetDisasm(jmp_addr)
                            while jmp_diasm.startswith("jmp     sub_14"):
                                jmp_addr = GetOperandValue(jmp_addr, 0)
                                jmp_diasm = GetDisasm(jmp_addr)

                            addr = hex(jmp_addr - 0x140000000).rstrip("L")
                            print("{", hex(ref.frm - 0x140000000).rstrip("L"), ", ", addr, "},")

        sys.stdout = oldout


def ret_zero():
    with open('ret_zero.txt', 'w') as f:
        oldout = sys.stdout
        sys.stdout = f
        funcea = 0x1401AB3C0
        i = 0
        for ref in XrefsTo(funcea):
            disasm = GetDisasm(ref.frm)
            if disasm.startswith("call    ?Term"):
                i = i + 1
                used_at_address = ref.frm - 0x140000000
                print("{", hex(used_at_address).rstrip("L"), "},")

        sys.stdout = oldout

    print(i)

def call_ret_zero():
    with open('call_xor_al_al.txt', 'w') as f:
        oldout = sys.stdout
        sys.stdout = f
        funcea = 0x1401B5990
        i = 0
        for ref in XrefsTo(funcea):
            disasm = GetDisasm(ref.frm)
            if disasm.startswith("call    ?Reserve") and get_item_size(ref.frm) == 5:
                i = i + 1
                used_at_address = ref.frm - 0x140000000
                print("{", hex(used_at_address).rstrip("L"), "},")

        sys.stdout = oldout

def jmp_ret_zero():
    with open('jmp_xor_al_al.txt', 'w') as f:
        oldout = sys.stdout
        sys.stdout = f
        funcea = 0x1401B5990
        i = 0
        for ref in XrefsTo(funcea):
            disasm = GetDisasm(ref.frm)
            if disasm.startswith("jmp     ?Reserve"):
                i = i + 1
                used_at_address = ref.frm - 0x140000000
                print("{", hex(used_at_address).rstrip("L"), "},")

        sys.stdout = oldout



def rax_rcx():
    with open('rax_rcx.txt', 'w') as f:
        oldout = sys.stdout
        sys.stdout = f
        funcea = 0x1401ABA20
        i = 0
        for ref in XrefsTo(funcea):
            disasm = GetDisasm(ref.frm)
            if disasm.startswith("call    sub"):
                i = i + 1
                used_at_address = ref.frm - 0x140000000
                if get_item_size(ref.frm) == 5:
                    print("\t\t{", hex(used_at_address).rstrip("L"), "},")

        sys.stdout = oldout

def rax_rcx_p():
    with open('rax_rcx_p.txt', 'w') as f:
        oldout = sys.stdout
        sys.stdout = f
        funcea = 0x1401C1520
        i = 0
        for ref in XrefsTo(funcea):
            disasm = GetDisasm(ref.frm)
            if disasm.startswith("call    sub"):
                i = i + 1
                used_at_address = ref.frm - 0x140000000
                if get_item_size(ref.frm) == 5:
                    print("\t\t{", hex(used_at_address).rstrip("L"), "},")

        sys.stdout = oldout

def jmp_rax():
    with open('jmp_rax.txt', 'w') as f:
        oldout = sys.stdout
        sys.stdout = f
        funcea = 0x142E77550
        i = 0
        for ref in XrefsTo(funcea):
            disasm = GetDisasm(ref.frm)
            if disasm.startswith("call    sub"):
                i = i + 1
                used_at_address = ref.frm - 0x140000000
                if get_item_size(ref.frm) == 5:
                    print("\t\t{", hex(used_at_address).rstrip("L"), "},")

        sys.stdout = oldout

def lock_inc():
    with open('lock_inc.txt', 'w') as f:
        oldout = sys.stdout
        sys.stdout = f
        funcea = 0x1403EE100
        i = 0
        for ref in XrefsTo(funcea):
            disasm = GetDisasm(ref.frm)
            if disasm.startswith("call    sub"):
                i = i + 1
                used_at_address = ref.frm - 0x140000000
                if get_item_size(ref.frm) == 5:
                    print("\t\t{", hex(used_at_address).rstrip("L"), "},")

        sys.stdout = oldout

def rax_rcx_8():
    with open('rax_rcx_8.txt', 'w') as f:
        oldout = sys.stdout
        sys.stdout = f
        funcea = 0x1401ED900
        i = 0
        for ref in XrefsTo(funcea):
            disasm = GetDisasm(ref.frm)
            if disasm.startswith("call    ?getpDC"):
                i = i + 1
                used_at_address = ref.frm - 0x140000000
                if get_item_size(ref.frm) == 5:
                    print("\t\t{", hex(used_at_address).rstrip("L"), "},")

        sys.stdout = oldout

def rax_rcx_68():
    with open('rax_rcx_68.txt', 'w') as f:
        oldout = sys.stdout
        sys.stdout = f
        funcea = 0x140213F00
        i = 0
        for ref in XrefsTo(funcea):
            disasm = GetDisasm(ref.frm)
            if disasm.startswith("call    sub"):
                i = i + 1
                used_at_address = ref.frm - 0x140000000
                if get_item_size(ref.frm) == 5:
                    print("\t\t{", hex(used_at_address).rstrip("L"), "},")

        sys.stdout = oldout

def eax_rcx_74():
    with open('eax_rcx_74.txt', 'w') as f:
        oldout = sys.stdout
        sys.stdout = f
        funcea = 0x1402139A0
        i = 0
        for ref in XrefsTo(funcea):
            disasm = GetDisasm(ref.frm)
            if disasm.startswith("call    sub"):
                i = i + 1
                used_at_address = ref.frm - 0x140000000
                if get_item_size(ref.frm) == 5:
                    print("\t\t{", hex(used_at_address).rstrip("L"), "},")

        sys.stdout = oldout

def show_func_order():
    with open('funcs.txt', 'w') as f:
        oldout = sys.stdout
        sys.stdout = f
        funcs_dic = {}
        funcs = Functions()
        for f in funcs:
            if  get_func_attr(f, FUNCATTR_END) -  get_func_attr(f, FUNCATTR_START) <= 5:
                name = get_name(f)
                i = 0
                for ref in XrefsTo(f):
                    if GetDisasm(ref.frm).startswith("call "):
                        i = i + 1
                funcs_dic[name] = i

        funcs_dic = OrderedDict(sorted(funcs_dic.items(), key=lambda x: x[1]))

        for k,v in funcs_dic.items():
            print (k, " : ", v)

        sys.stdout = oldout



#eax_rcx_74()